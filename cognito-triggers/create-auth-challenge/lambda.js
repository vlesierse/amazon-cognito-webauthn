const fido2 = require('../../lib/fido2');
const base64url = require('base64url');

exports.handler = async (event) => {
    console.log("Create Auth Challenge: " + JSON.stringify(event));
    if (event.request.challengeName == 'CUSTOM_CHALLENGE') {
        if (event.request.userAttributes['custom:authenticators']) {
            authenticators = JSON.parse(base64url.decode(event.request.userAttributes['custom:authenticators']));
            const authenticationRequest = fido2.generateServerGetAssertion(authenticators);
            console.log("Authentication request: " + JSON.stringify(authenticationRequest));
            event.response.challengeMetadata = 'WEBAUTHN_CHALLENGE';
            event.response.publicChallengeParameters = {
                challenge: encodeURI(JSON.stringify(authenticationRequest)),
                challengeType: "GET"
            };
            event.response.privateChallengeParameters = {
                challenge: authenticationRequest.challenge
            };
        } else {
            const { email, sub, name } = event.request.userAttributes;
            const registrationRequest = fido2.generateServerMakeCredRequest(email, name, sub);
            console.log("Registration request: " + JSON.stringify(registrationRequest));
            event.response.challengeMetadata = 'WEBAUTHN_CHALLENGE';
            event.response.publicChallengeParameters = {
                challenge:  encodeURI(JSON.stringify(registrationRequest)),
                challengeType: "CREATE"
            };
            event.response.privateChallengeParameters = {
                challenge: registrationRequest.challenge
            };
        }
        console.log("Create Auth Challenge Reponse: " + JSON.stringify(event));
    }
    return event;
}