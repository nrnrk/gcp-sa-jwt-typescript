import axios from 'axios'
import jwt from 'jsonwebtoken'
import NodeRSA from 'node-rsa'
import { format } from 'util'
import { Buffer } from 'buffer'

// jwkEndpoint is endpoint to fetch JWK of a Google API Service Account
// `%s` should be replaced with a service account email
const jwkEndpoint = 'https://www.googleapis.com/service_accounts/v1/jwk/%s'

interface Cert {
  kid: string,
  kty: string,
  alg: string,
  e: string,
  n: string,
}

interface CertsResponse {
  keys: Cert[],
}

// glimpseClaims returns service accoutn email & key id from token without verification
function glimpseClaims(token: string): { saEmail: string, keyId: string } {
  console.log('glimpse!')
  // decode JWT *without verification*
  const claims = jwt.decode(token, { complete: true })
  if (!claims) {
    throw new Error('Could not decode token');
  }
  if (typeof claims === 'string') {
    throw new Error('Could not get email & key id from token');
  }
  const header = claims['header'] as jwt.JwtHeader
  const payload = claims['payload'] as { [key: string]: any }

  return {
    saEmail: payload['iss'] as string,
    keyId: header.kid || '',
  }
}

async function fetchCert(saEmail: string, keyId: string): Promise<Cert> {
  const res = await axios.get<CertsResponse>(format(jwkEndpoint, saEmail))
  return res.data.keys.filter(cert => cert.kid === keyId)?.[0]
}

function main() {
  // JWT token of Google Service Account
  const token: string = process.argv[2];
  console.log(`token: ${token} `)

  // Get service account email & key id
  const { saEmail, keyId } = glimpseClaims(token)
  console.log(saEmail, keyId)

  const key = new NodeRSA()
  fetchCert(saEmail, keyId)
    .then(cert =>
      key.importKey({
        n: Buffer.from(cert.n, 'base64'),
        e: Buffer.from(cert.e, 'base64'),
      }, 'components-public')
        .exportKey('pkcs8-public-pem')
    )
    .catch(err => console.error(`Could not fetch certs: ${err} `))
    .then(pem =>
      jwt.verify(token, pem || '', function (err, decoded) {
        if (err) {
          throw new Error(`Could not verify JWT token`)
        }
        console.log(decoded)
      })
    )
}

main()
