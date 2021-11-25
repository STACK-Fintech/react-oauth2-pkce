/* eslint-disable @typescript-eslint/camelcase */
import { createPKCECodes, PKCECodePair } from './pkce'
import { toUrlEncoded } from './util'

import jwtDecode from 'jwt-decode'

export interface AuthServiceProps {
  clientId: string
  clientSecret?: string
  contentType?: string
  location: Location
  provider: string
  authorizeEndpoint?: string
  tokenEndpoint?: string
  logoutEndpoint?: string
  audience?: string
  redirectUri?: string
  scopes: string[]
  autoRefresh?: boolean
  refreshSlack?: number
}

export interface AuthClientConfig {
  pkce: PKCECodePair
  auth: AuthTokens | any
  props: AuthServiceProps
  preAuthUri: string
}

export interface AuthClientConfigMap {
  [key: string] : AuthClientConfig
}

export interface AuthTokens {
  id_token: string
  access_token: string
  refresh_token: string
  expires_in: number
  expires_at?: number // calculated on login
  token_type: string
}

export interface AuthTokensMap {
  [key: string]: AuthTokens
}

export interface JWTIDToken {
  given_name: string
  family_name: string
  name: string
  email: string
}

export interface TokenRequestBody {
  clientId: string
  grantType: string
  redirectUri?: string
  refresh_token?: string
  clientSecret?: string
  code?: string
  codeVerifier?: string
}

export class AuthService<TIDToken = JWTIDToken> {
  props: AuthServiceProps
  timeout?: number

  constructor(props: AuthServiceProps) {
    if (!props || !props.clientId)
      throw new Error("Configuration must include clientId!")
   
    const clientId = props.clientId
    const clientConfig = this.getClientConfig(clientId)
    clientConfig.props = props
    this.setClientConfig(clientId, clientConfig)
    this.props = props
    const code = this.getCodeFromLocation(window.location)
    if (code !== null) {
      this.fetchToken(clientId, code)
        .then(() => {
          this.restoreUri(clientId)
        })
        .catch((e) => {
          this.clearClientConfig(clientId)
          this.removeCodeFromLocation()
          console.warn({ e })
        })
    } else if (clientConfig.props.autoRefresh) {
      this.startTimer(clientId)
    }
  }

  getUser(clientId: string): {} {
    const t = this.getAuthTokens(clientId)
    if (null === t) return {}
    const decoded = jwtDecode(t.id_token) as TIDToken
    return decoded
  }

  getCodeFromLocation(location: Location): string | null {
    const split = location.toString().split('?')
    if (split.length < 2) {
      return null
    }
    const pairs = split[1].split('&')
    for (const pair of pairs) {
      const [key, value] = pair.split('=')
      if (key === 'code') {
        return decodeURIComponent(value || '')
      }
    }
    return null
  }

  removeCodeFromLocation(): void {
    const [base, search] = window.location.href.split('?')
    if (!search) {
      return
    }
    const newSearch = search
      .split('&')
      .map((param) => param.split('='))
      .filter(([key]) => key !== 'code')
      .map((keyAndVal) => keyAndVal.join('='))
      .join('&')
    window.history.replaceState(
      window.history.state,
      'null',
      base + (newSearch.length ? `?${newSearch}` : '')
    )
  }

  getItem(key: string): string | null {
    return window.localStorage.getItem(key)
  }
  removeItem(key: string): void {
    window.localStorage.removeItem(key)
  }

  getAllClientConfigs() : AuthClientConfigMap {
    return JSON.parse(window.localStorage.getItem('clients') || '{}')
  }

  clearClientConfig(clientId: string) {
    const configs = this.getAllClientConfigs()
    delete configs[clientId]
    return window.localStorage.setItem('clients', JSON.stringify(configs))
  }

  getClientConfig(clientId: string): AuthClientConfig {
    return this.getAllClientConfigs()[clientId] || {}
  }

  setClientConfig(clientId: string, config: AuthClientConfig) {
    const configs = this.getAllClientConfigs()
    configs[clientId] = config;
    window.localStorage.setItem('clients', JSON.stringify(configs));
  }

  getPkce(clientId: string): PKCECodePair {
    const pkce = window.localStorage.getItem(`${clientId}:pkce`)
    if (null === pkce) {
      throw new Error('PKCE pair not found in local storage')
    } else {
      return JSON.parse(pkce)
    }
  }

  setPkce(clientId: string, pkce: PKCECodePair) {
    const clientConfig = this.getClientConfig(clientId);
    clientConfig.pkce = pkce;
    this.setClientConfig(clientId, clientConfig);
  }

  clearAuthTokens(clientId: string) {
    const config = this.getClientConfig(clientId);
    config.auth = {}
    this.setClientConfig(clientId, config)
  }

  setAuthTokens(clientId: string, auth: AuthTokens): void {
    const { refreshSlack = 5 } = this.props
    const now = new Date().getTime()
    auth.expires_at = now + (auth.expires_in + refreshSlack) * 1000
    const clientConfig = this.getClientConfig(clientId);
    clientConfig.auth = auth
    this.setClientConfig(clientId, clientConfig);
  }

  getAuthTokens(clientId: string): AuthTokens {
    return this.getClientConfig(clientId).auth
  }
  
  getAllAuthTokens() : AuthTokensMap {
    const clientConfigs = this.getAllClientConfigs()
    const authTokens = {}
    for (const c of Object.keys(clientConfigs)) {
      authTokens[c] = clientConfigs[c]
    }
    return authTokens
  }

  setPreAuthUri(clientId: string, preAuthUri: string) {
    const config = this.getClientConfig(clientId)
    config.preAuthUri = preAuthUri
    this.setClientConfig(clientId, config)
  }

  getPreAuthUri(clientId: string) {
    return this.getClientConfig(clientId).preAuthUri
  }

  clearPreAuthUri(clientId: string) {
    const config = this.getClientConfig(clientId);
    config.preAuthUri = ""
    this.setClientConfig(clientId, config)
  }

  isPending(clientId: string): boolean {
    return (
      window.localStorage.getItem(`${clientId}:pkce`) !== null &&
      window.localStorage.getItem(`${clientId}:auth`) === null
    )
  }

  isAuthenticated(clientId: string): boolean {
    return window.localStorage.getItem(`${clientId}:auth`) !== null
  }

  async logout(shouldEndSession: boolean = false): Promise<boolean> {
    this.removeItem('pkce')
    this.removeItem('auth')
    if (shouldEndSession) {
      const { clientId, provider, logoutEndpoint, redirectUri } = this.props;
      const query = {
        client_id: clientId,
        post_logout_redirect_uri: redirectUri
      }
      const url = `${logoutEndpoint || `${provider}/logout`}?${toUrlEncoded(query)}`
      window.location.replace(url)
      return true;
    } else {
      window.location.reload()
      return true
    }
  }

  async login(): Promise<void> {
    this.authorize()
  }

  // this will do a full page reload and to to the OAuth2 provider's login page and then redirect back to redirectUri
  authorize(arg?: any): boolean {
    const { clientId, provider, authorizeEndpoint, redirectUri, scopes, audience, state } = arg ? arg : this.props;


    const pkce = createPKCECodes()
    this.setPkce(clientId, pkce)
    this.setPreAuthUri(clientId, location.href)
    this.clearAuthTokens(clientId)
    const codeChallenge = pkce.codeChallenge

    const query = {
      clientId,
      scope: scopes.join(' '),
      responseType: 'code',
      redirectUri,
      ...(audience && { audience }),
      codeChallenge,
      codeChallengeMethod: 'S256',
      state: state
    }
    // Responds with a 302 redirect
    const url = `${authorizeEndpoint || `${provider}/authorize`}?${toUrlEncoded(query)}`
    window.location.replace(url)
    return true
  }

  // this happens after a full page reload. Read the code from localstorage
  async fetchToken(clientId: string, code: string, isRefresh = false): Promise<AuthTokens> {

      const clientConfig = this.getClientConfig(clientId)
      const {
        clientSecret,
        contentType,
        provider,
        tokenEndpoint,
        redirectUri,
        autoRefresh = true
      } = clientConfig.props
    
      const grantType = 'authorization_code'

      let payload: TokenRequestBody = {
        clientId,
        ...(clientSecret ? { clientSecret } : {}),
        redirectUri,
        grantType
      }
      if (isRefresh) {
        payload = {
          ...payload,
          grantType: 'refresh_token',
          refresh_token: code
        }
      } else {
        const pkce: PKCECodePair = this.getPkce(clientId)
        const codeVerifier = pkce.codeVerifier
        payload = {
          ...payload,
          code,
          codeVerifier
        }
      }

      const response = await fetch(`${tokenEndpoint || `${provider}/token`}`, {
        headers: {
          'Content-Type': contentType || 'application/x-www-form-urlencoded'
        },
        method: 'POST',
        body: toUrlEncoded(payload)
      })
      this.removeItem('pkce')
      let json = await response.json()
      if (isRefresh && !json.refresh_token) {
        json.refresh_token = payload.refresh_token
      }
      this.setAuthTokens(clientId, json as AuthTokens)
      if (autoRefresh) {
        this.startTimer(clientId)
      }
    return this.getAuthTokens(clientId)
  }

  armRefreshTimer(clientId: string, refreshToken: string, timeoutDuration: number): void {
    if (this.timeout) {
      clearTimeout(this.timeout)
    }
    this.timeout = window.setTimeout(() => {
      this.fetchToken(clientId, refreshToken, true)
        .then(({ refresh_token: newRefreshToken, expires_at: expiresAt }) => {
          if (!expiresAt) return
          const now = new Date().getTime()
          const timeout = expiresAt - now
          if (timeout > 0) {
            this.armRefreshTimer(clientId, newRefreshToken, timeout)
          } else {
            this.removeItem('auth')
            this.removeCodeFromLocation()
          }
        })
        .catch((e) => {
          this.removeItem('auth')
          this.removeCodeFromLocation()
          console.warn({ e })
        })
    }, timeoutDuration)
  }

  startTimer(clientId: string): void {
    const authTokens = this.getAuthTokens(clientId)
    if (!authTokens) {
      return
    }
    const { refresh_token: refreshToken, expires_at: expiresAt } = authTokens
    if (!expiresAt || !refreshToken) {
      return
    }
    const now = new Date().getTime()
    const timeout = expiresAt - now
    if (timeout > 0) {
      this.armRefreshTimer(clientId, refreshToken, timeout)
    } else {
      this.removeCodeFromLocation()
    }
  }

  restoreUri(clientId: string): void {
    const uri = this.getPreAuthUri(clientId)
    this.clearPreAuthUri(clientId)
    console.log({ uri })
    if (uri !== null) {
      window.location.replace(uri)
    }
    this.removeCodeFromLocation()
  }
}
