import { ExpressReceiver, AuthorizeResult } from '@slack/bolt';
import { WebClient } from '@slack/web-api';
import { Response } from 'express';

export interface AuthorizeSuccessResult {
  res: Response;
  oAuthResult: AuthorizeResult;
}

export interface AuthorizationRequest {
  clientId: string;
  clientSecret: string;
  signingSecret: string;
  redirectUrl: string;
  stateCheck(oAuthState: string): boolean;
  onSuccess(result: AuthorizeSuccessResult): Promise<void>;
  onError(error: Error): Promise<void>;
  useSlackOauthV2: boolean;
}

const Auth = (auth: AuthorizationRequest) => {
  const {
    clientId,
    clientSecret,
    signingSecret,
    redirectUrl,
    stateCheck,
    onSuccess,
    onError,
    useSlackOauthV2,
  } = auth;

  // custom receiver
  const receiver = new ExpressReceiver({ signingSecret });

  // the express app
  const expressApp = receiver.app;

  // the oauth callback
  const callbackUrl = new URL(redirectUrl);
  expressApp.get(callbackUrl.pathname, async (req, res) => {
    const state = req.query.state as string;

    if (!state) {
      await onError(new Error('State query parameter is not defined!'));
      return;
    }

    const stateIsValid = stateCheck(state);

    // if not valid, throw error
    if (!stateIsValid) {
      await onError(new Error('Invalid state.'));
      return;
    }

    // get tokens
    const webClient = new WebClient();
    const method = useSlackOauthV2
      ? webClient.oauth.v2.access
      : webClient.oauth.access;

    try {
      const oAuthResult = await method({
        client_id: clientId,
        client_secret: clientSecret,
        code: req.query.code as string,
        redirect_url: redirectUrl,
      });
      await onSuccess({ res, oAuthResult });
    } catch (error) {
      await onError(error);
    }
  });

  return receiver;
};

export default Auth;
