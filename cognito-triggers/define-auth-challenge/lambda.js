exports.handler = async (event, context) => {

  console.log("Define Auth Challenge: " + JSON.stringify(event));

  if (event.request.session &&
      event.request.session.length &&
      event.request.session.slice(-1)[0].challengeResult === true) {
      // The user provided the right answer; succeed auth
      event.response.issueTokens = true;
      event.response.failAuthentication = false;
  } else {
      // The user did not provide a correct answer yet; present challenge
      event.response.issueTokens = false;
      event.response.failAuthentication = false;
      event.response.challengeName = 'CUSTOM_CHALLENGE';
  }

  return event;
}