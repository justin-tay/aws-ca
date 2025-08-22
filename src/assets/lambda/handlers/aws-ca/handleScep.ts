import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { loadCertificateChain } from './ca/loadCertificateChain';
import { getConfig } from './ca/getConfig';
import { exportPkcs7CertificateChainBinary } from './ca/exportPkcs7CertificateChainBinary';
import {
  Certificate,
  ContentInfo,
  EnvelopedData,
  getCrypto,
  id_ContentType_Data,
  id_ContentType_EnvelopedData,
  id_ContentType_SignedData,
  SignedData,
} from 'pkijs';
import { fromBER } from 'asn1js';
import { loadSubCa } from './ca/loadSubCa';
import { Pkcs10CertificateRequest } from '@peculiar/x509';
import { issueCertificate } from './ca/issueCertificate';
import { getCACert } from './scep/getCaCert';
import { ScepMessageType } from './scep/ScepMessageType';

const id_Attributes_MessageType = '2.16.840.1.113733.1.9.2'; // {id-attributes messageType(2)}

export async function handleScep(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  const crypto = getCrypto(true);
  const { headers, body, httpMethod, queryStringParameters, isBase64Encoded } =
    event;
  const operation = queryStringParameters?.operation;
  if (!operation) {
    return {
      statusCode: 400,
      body: 'Missing "operation" parameter.',
    };
  }
  let message;
  if (httpMethod === 'GET') {
    if (queryStringParameters?.message) {
      message = Buffer.from(
        decodeURIComponent(queryStringParameters.message),
        'base64',
      );
    } else {
      message = null;
    }
  } else if (httpMethod === 'POST') {
    if (body) {
      message = isBase64Encoded
        ? Buffer.from(body, 'base64')
        : Buffer.from(body);
    } else {
      message = null;
    }
  } else {
    return {
      statusCode: 405,
      body: 'Method Not Allowed',
    };
  }
  if (operation === 'GetCACaps') {
    const caps = 'AES\r\nPOSTPKIOperation\r\nSCEPStandard\r\nSHA-256';
    return {
      headers: {
        'Content-Type': 'text/plain',
        'Content-Length': caps.length,
      },
      statusCode: 200,
      body: caps,
    };
  } else if (operation === 'GetCACert') {
    const certificateChain = await loadCertificateChain({
      issuerName: getConfig().subCaName,
    });
    return await getCACert({ certificateChain });
  } else if (operation === 'PKIOperation') {
    if (!message) {
      return {
        statusCode: 400,
        body: 'Message must be specified',
      };
    }
    if (httpMethod === 'POST') {
      const contentType = headers['Content-Type'] ?? headers['content-type'];
      if (
        contentType !== 'application/x-pki-message' &&
        contentType !== 'application/octet-stream' // jscep
      ) {
        return {
          statusCode: 415,
          body: 'Unsupported Media Type',
        };
      }
    }
    const pkiMessage = ContentInfo.fromBER(message);
    if (pkiMessage.contentType !== id_ContentType_SignedData) {
      return {
        statusCode: 400,
        body: 'pkiMessage contentType must be signedData',
      };
    }
    const signedData = new SignedData({ schema: pkiMessage.content });
    if (signedData.encapContentInfo.eContentType !== id_ContentType_Data) {
      return {
        statusCode: 400,
        body: 'signedData eContentType must be data',
      };
    }
    signedData.verify({ signer: 0 });
    const messageTypeAttribute =
      signedData.signerInfos[0].signedAttrs?.attributes.find(
        (attribute) => attribute.type === id_Attributes_MessageType,
      );
    if (!messageTypeAttribute) {
      return {
        statusCode: 400,
        body: 'messageType must be included in all PKI messages',
      };
    }
    const messageType = messageTypeAttribute.values[0].getValue();
    if (signedData.encapContentInfo.eContent) {
      const subCa = await loadSubCa();
      if (subCa.certificate.privateKey) {
        const pkcsPKIEnvelope = ContentInfo.fromBER(
          signedData.encapContentInfo.eContent.getValue(),
        );
        if (pkcsPKIEnvelope.contentType !== id_ContentType_EnvelopedData) {
          return {
            statusCode: 400,
            body: 'signedData encapContentInfo eContent contentType must be envelopedData',
          };
        }
        const envelopedData = new EnvelopedData({
          schema: pkcsPKIEnvelope.content,
        });
        const recipientCertificate = new Certificate({
          schema: fromBER(subCa.certificate.rawData).result,
        });
        let recipientPrivateKey = await crypto.subtle.exportKey(
          'pkcs8',
          subCa.certificate.privateKey,
        ); // key needs to be exported to der as rsa key usage is sign not decrypt
        const decrypted = await envelopedData.decrypt(0, {
          recipientCertificate,
          recipientPrivateKey,
        });
        const csr = new Pkcs10CertificateRequest(decrypted);
        if (messageType === ScepMessageType.PKCSReq) {
          const result = await issueCertificate({
            csr,
            validity: 3,
            profile: 'client',
          });
          if (result) {
            const certificateChain = await loadCertificateChain({
              issuerName: result.certificate.issuerName.toString(),
            });
            const content = await exportPkcs7CertificateChainBinary({
              certificateChain: [result.certificate, ...certificateChain],
            });
            return {
              headers: {
                'Content-Type': 'application/x-pki-message',
                'Content-Length': content.byteLength,
              },
              statusCode: 200,
              body: Buffer.from(content).toString('base64'),
              isBase64Encoded: true,
            };
          }
        }
      }
    }
  }
  return {
    statusCode: 400,
    body: 'Unsupported "operation"',
  };
}
