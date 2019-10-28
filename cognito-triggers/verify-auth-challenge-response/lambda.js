const AWS = require('aws-sdk');
const fido2 = require('../../lib/fido2');
const base64url = require('base64url');

const cognito = new AWS.CognitoIdentityServiceProvider();

const storeAuthenticator = async (authenticators, userPoolId, userName) => {
    return cognito.adminUpdateUserAttributes(
        {
          UserAttributes: [
            {
              Name: 'custom:authenticators',
              Value: base64url.encode(JSON.stringify(authenticators))
            }
          ],
          UserPoolId: userPoolId,
          Username: userName
        }
      ).promise();
}

exports.handler = async (event, context) => {
    console.log("Verify Auth Challenge: " + JSON.stringify(event));

    event.response.answerCorrect = false;
    let authenticators = [];
    if (event.request.userAttributes['custom:authenticators']) {
        authenticators = JSON.parse(base64url.decode(event.request.userAttributes['custom:authenticators']));
    }
    if (authenticators.length > 0) {
        const response = fido2.verifyAuthenticatorAssertionResponse(JSON.parse(decodeURI(event.request.challengeAnswer)), authenticators);
        console.log("Verify Authentication Response: " + JSON.stringify(response));
        if (response.verified) {
          await storeAuthenticator(authenticators, event.userPoolId, event.userName);
          event.response.answerCorrect = true;
        }
    } else {
        const credentialResponse = JSON.parse(decodeURI(event.request.challengeAnswer));
        const response = fido2.verifyAuthenticatorAttestationResponse(credentialResponse);
        console.log("Verify Authenticator Response: " + JSON.stringify(response));
        if (response.verified) {
            authenticators.push(response.authrInfo);
            await storeAuthenticator(authenticators, event.userPoolId, event.userName);
            event.response.answerCorrect = true;
        }
    }
    return event;
}