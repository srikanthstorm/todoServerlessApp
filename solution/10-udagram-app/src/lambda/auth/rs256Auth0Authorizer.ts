
import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

const cert = `-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIJcaiSTYUVjhRGMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV
BAMTFmRldi1sNjhkYXVsMC5hdXRoMC5jb20wHhcNMjAwNDAyMTQwMDU4WhcNMzMx
MjEwMTQwMDU4WjAhMR8wHQYDVQQDExZkZXYtbDY4ZGF1bDAuYXV0aDAuY29tMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxpsnQM8OCvYN5UZNG96sddUv
/6W5R21JZWChxnhfP/TD9L4UhW2mBhCQ8ipAtgqnxTqPV9ecReIIgoWHwlsk/9R8
VMBgZv4S5T1bTPBbC+G4OmyRCbyZwdqeC+TUGVHKyEAfM293mduX+e8+i9O1+GYv
ElUmyRlgmozkZRzH4zCPTOslVRyJ1jqaUaAJgoxJY2ALo68xR5zqgt9IwpBF+Mgb
8Ax7b59VJf8B2WxItWYcVQvkRaiaG5S9fkha2Ui4bRCzCQhAjrKkS48w4E/ndlwb
CRhNikWmD6DWWz71f8KEUFeLAeCmXMdG8GRi+D1h3JME6uHWmxia9WGkWMUa/QID
AQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQEpGPzVSm3CLv0s4Ag
vp06nEXz9zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAH8oFCWh
Q0dWri0zwejj6tlBML6+u9/zLCiY2v0WTQ1UpPay5o3J3j6OYBcdHfcT5RFW9EVr
PTgtjruekSlrQNWm3oRsRNo9gQ6S5G3zx0woCTlkTbQQiOcSsNhgjrjMIoMPfhgP
PCipH+/f6nWz70pWth9RoBR/JijmWiR9LjSWDTmeP6eWVxn6heMAFaw47uAC9D/p
fLe65DufYJlIsGi9LOkwyFROJ7iTwb8P1LS1xvbaHYXFMxi+3fyfp6y6S1oJdYXd
mF4acTjD08WKpt48TmtTV/fnWl36NUucgV9ytHCMs7K/O/ZCcXHGqkiKDPqKfgmi
lIBlCWwyzj5kOhY=
-----END CERTIFICATE-----`

export const handler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  try {
    const jwtToken = verifyToken(event.authorizationToken)
    console.log('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    console.log('User authorized', e.message)

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

function verifyToken(authHeader: string): JwtToken {
  if (!authHeader)
    throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return verify(token, cert, { algorithms: ['RS256'] }) as JwtToken
}
