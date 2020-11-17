const aws = require('aws-amplify');
const jwtDecode = require('jwt-decode');

function printLog(message) {
  console.debug('[AWS Amplify Auth] ' + message);
}

function validateArg(name, value) {
  if (!value) {
    throw new Error(name + ' is required')
  }
}

function buildCookie(userData) {
  const {
    keyPrefix,
    username,
    idToken,
    accessToken
  } = userData;

  const userKeyPrefix = keyPrefix + '.' + username;

  const lastAuthUserField = keyPrefix + '.LastAuthUser=' + username;
  const idTokenField = userKeyPrefix + '.idToken=' + idToken;
  const accessTokenField = userKeyPrefix + '.accessToken=' + accessToken;

  return lastAuthUserField + '; ' + idTokenField + '; ' + accessTokenField;
}

function validateToken(token) {
  const now = Date.now().valueOf() / 1000;

  try {
    const tokenData = jwtDecode(token);
    printLog('Validating token - now: ' + now + ', exp: ' + tokenData.exp);
    
    // Invalid if token has expired
    if (typeof tokenData.exp !== 'undefined' && tokenData.exp < now) {
      return false;
    }

    return true;
  } catch (e) {
    return false;
  }
}

async function runAwsAmplifyAuthCookie(context, Username, Password, Region, UserPoolId, WebClientId) {
  validateArg('Username', Username);
  validateArg('Password', Password);
  validateArg('Region', Region);
  validateArg('UserPoolId', UserPoolId);
  validateArg('WebClientId', WebClientId);

  // Check for existing valid token first
  const storeKey = [Username, Password, Region, UserPoolId, WebClientId].join(';');
  const storedUserDataStr = await context.store.getItem(storeKey);
  printLog('Retrieved stored data: ' + storedUserDataStr);

  if (storedUserDataStr) {
    const storedUserData = JSON.parse(storedUserDataStr);
    if (storedUserData.error) {
      printLog('Stored token error: ' + storedUserData.error);
    } else if (!validateToken(storedUserData.accessToken)) {
      printLog('Token expired, refreshing');
    } else {
      printLog('Using stored token');
      return buildCookie(storedUserData);
    }
  }

  aws.Amplify.configure({
    Auth: {
      region: Region,
      userPoolId: UserPoolId,
      userPoolWebClientId: WebClientId
    },
  });

  // If no valid existing token, sign in
  try {
    const user = await aws.Auth.signIn(Username, Password);
    const userData = {
      keyPrefix: user.keyPrefix,
      username: user.username,
      idToken: user.signInUserSession.idToken.jwtToken,
      accessToken: user.signInUserSession.accessToken.jwtToken,
    };

    const userDataStr = JSON.stringify(userData);
    printLog('Storing token data: ' + userDataStr);
    await context.store.setItem(storeKey, userDataStr);

    return buildCookie(userData);
  } catch (e) {
    const errorData = { error: e.message };
    const errorDataStr = JSON.stringify(errorData);
    printLog('Storing error data: ' + errorDataStr);
    await context.store.setItem(storeKey, errorDataStr);

    return e.message;
  }
}

module.exports.templateTags = [
  {
    run: runAwsAmplifyAuthCookie,
    name: 'AwsAmplifyAuthCookie',
    displayName: 'AWS Amplify Auth Cookie',
    description: 'Insomnia plugin to create an auth cookie for AWS Amplify',
    args: [
      {
        displayName: 'Username',
        type: 'string',
        validate: (arg) => arg ? '' : 'Required',
      },
      {
        displayName: 'Password',
        type: 'string',
        validate: (arg) => arg ? '' : 'Required',
      },
      {
        displayName: 'Region',
        type: 'string',
        validate: (arg) => arg ? '' : 'Required',
      },
      {
        displayName: 'UserPoolId',
        type: 'string',
        validate: (arg) => arg ? '' : 'Required',
      },
      {
        displayName: 'WebClientId',
        type: 'string',
        validate: (arg) => arg ? '' : 'Required',
      },
    ],
  },
];
