import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  BasicOCSPResponse,
  OCSPRequest,
  OCSPResponse,
  RelativeDistinguishedNames,
  ResponseBytes,
  SingleResponse,
  id_PKIX_OCSP_Basic,
} from 'pkijs';
import { Convert } from 'pvtsutils';
import {
  Enumerated,
  OctetString,
  Primitive,
  Constructed,
  GeneralizedTime,
} from 'asn1js';
import { getConfig } from './ca/getConfig';
import { loadSubCa } from './ca/loadSubCa';
import { QueryCommand } from '@aws-sdk/lib-dynamodb';
import { getDynamoDBDocumentClient } from './ca/getDynamoDBDocumentClient';
import CertificateStatus from './ca/CertificateStatus';
import { X509CrlReason } from '@peculiar/x509';

export async function handleOcsp(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  const { headers, body, httpMethod } = event;
  let ocspRequest;
  if (httpMethod === 'GET') {
    ocspRequest = OCSPRequest.fromBER(
      Buffer.from(
        event.path.substring(event.path.lastIndexOf('/') + 1),
        'base64',
      ),
    ); // base64 encoded
  } else if (httpMethod === 'POST') {
    if (
      headers['Content-Type'] !== 'application/ocsp-request' &&
      headers['content-type'] !== 'application/ocsp-request'
    ) {
      return {
        statusCode: 415,
        body: 'Unsupported Media Type',
      };
    }
    if (!body) {
      return {
        statusCode: 400,
        body: 'Required certificate signing request body is missing',
      };
    }
    if (!event.isBase64Encoded) {
      return {
        statusCode: 400,
        body: 'Expected binary body',
      };
    }
    ocspRequest = OCSPRequest.fromBER(Buffer.from(body, 'base64')); // binary der
  } else {
    return {
      statusCode: 405,
      body: 'Method Not Allowed',
    };
  }

  const subCa = await loadSubCa();
  const docClient = getDynamoDBDocumentClient();

  const basicOcspResponse = new BasicOCSPResponse();

  basicOcspResponse.tbsResponseData.responderID =
    new RelativeDistinguishedNames({
      valueBeforeDecode: subCa.certificate?.subjectName.toArrayBuffer(),
    });
  basicOcspResponse.tbsResponseData.producedAt = new Date();

  for (const request of ocspRequest.tbsRequest.requestList) {
    const certID = request.reqCert;
    const serialNumber = Convert.ToHex(
      request.reqCert.serialNumber.valueBlock.valueHexView,
    );

    const certificateCommand = new QueryCommand({
      TableName: getConfig().caIndexTableName,
      KeyConditionExpression:
        'IssuerName = :issuerName and SerialNumber = :serialNumber',
      ExpressionAttributeValues: {
        ':issuerName': getConfig().subCaName,
        ':serialNumber': serialNumber,
      },
      ConsistentRead: true,
    });

    const certificateResponse = await docClient.send(certificateCommand);

    const response = new SingleResponse({
      certID,
    });
    if (
      certificateResponse &&
      certificateResponse.Count &&
      certificateResponse.Count > 0 &&
      certificateResponse.Items
    ) {
      if (certificateResponse.Items[0].Status === CertificateStatus.Revoked) {
        response.certStatus = new Constructed({
          idBlock: {
            tagClass: 3,
            tagNumber: 1, // revoked
          },
          value: [
            new GeneralizedTime({
              valueDate: new Date(certificateResponse.Items[0].RevocationDate),
            }),
            new Constructed({
              optional: true,
              idBlock: {
                tagClass: 3,
                tagNumber: 0,
              },
              value: [
                new Enumerated({
                  value:
                    certificateResponse.Items[0].RevocationReason ??
                    X509CrlReason.unspecified,
                }),
              ],
            }),
          ],
        });
      } else if (
        certificateResponse.Items[0].Status === CertificateStatus.Expired
      ) {
        response.certStatus = new Primitive({
          idBlock: {
            tagClass: 3,
            tagNumber: 2, // unknown
          },
          lenBlock: { length: 1 },
        });
      } else {
        response.certStatus = new Primitive({
          idBlock: {
            tagClass: 3,
            tagNumber: 0, // good
          },
        });
      }
    }

    response.thisUpdate = new Date();

    basicOcspResponse.tbsResponseData.responses.push(response);
  }
  await basicOcspResponse.sign(subCa.certificate?.privateKey!, 'SHA-256');
  const basicOcspResponseRaw = basicOcspResponse.toSchema().toBER(false);

  const ocspResponse = new OCSPResponse({
    responseStatus: new Enumerated({ value: 0 }), // success
    responseBytes: new ResponseBytes({
      responseType: id_PKIX_OCSP_Basic,
      response: new OctetString({ valueHex: basicOcspResponseRaw }),
    }),
  });

  const ocspResponseRaw = ocspResponse.toSchema().toBER();

  return {
    headers: {
      'Content-Type': 'application/ocsp-response',
      'Content-Length': ocspResponseRaw.byteLength,
    },
    statusCode: 200,
    body: Buffer.from(ocspResponseRaw).toString('base64'),
    isBase64Encoded: true,
  };
}
