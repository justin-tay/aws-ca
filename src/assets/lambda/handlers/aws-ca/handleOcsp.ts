import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  BasicOCSPResponse,
  OCSPRequest,
  OCSPResponse,
  ResponseBytes,
  SingleResponse,
  id_PKIX_OCSP_Basic,
} from 'pkijs';
import { Enumerated, OctetString, Primitive } from 'asn1js';
import { getConfig } from './ca/getConfig';
import { loadSubCa } from './ca/loadSubCa';
import { QueryCommand } from '@aws-sdk/lib-dynamodb';
import { getDynamoDBDocumentClient } from './ca/getDynamoDBDocumentClient';
import CertificateStatus from './ca/CertificateStatus';

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

  basicOcspResponse.tbsResponseData.responderID = subCa.certificate?.subject;
  basicOcspResponse.tbsResponseData.producedAt = new Date();

  for (const request of ocspRequest.tbsRequest.requestList) {
    const certID = request.reqCert;
    const serialNumber = certID.serialNumber;

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

    let tagNumber = 2; // unknown
    let valueHex;
    if (
      certificateResponse &&
      certificateResponse.Count &&
      certificateResponse.Count > 0 &&
      certificateResponse.Items
    ) {
      if (certificateResponse.Items[0].Status === CertificateStatus.Revoked) {
        tagNumber = 1; // revoked
        // TODO create RevokedInfo
      } else if (
        certificateResponse.Items[0].Status === CertificateStatus.Expired
      ) {
        //tagNumber = 2; // unknown
      } else {
        tagNumber = 0; // good
      }
    }

    const response = new SingleResponse({
      certID,
    });
    response.certStatus = new Primitive({
      idBlock: {
        tagClass: 3,
        tagNumber,
      },
      valueHex,
    });
    response.thisUpdate = new Date();

    basicOcspResponse.tbsResponseData.responses.push(response);
  }

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
