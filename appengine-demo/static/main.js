'use strict';

var isPushEnabled = false;
var subscription;

function initialise() {
  if (!('showNotification' in ServiceWorkerRegistration.prototype)) {
    console.warn('Notifications aren\'t supported.');
    return;
  }

  if (Notification.permission === 'denied') {
    console.warn('The user has blocked notifications.');
    return;
  }

  if (!('PushManager' in window)) {
    console.warn('Push messaging isn\'t supported.');
    return;
  }

  navigator.serviceWorker.ready.then(function(serviceWorkerRegistration) {
    serviceWorkerRegistration.pushManager.getSubscription().then(function(s) {
        var toggleButton = document.querySelector('.toggle-push-button');
        toggleButton.disabled = false;

        if (!s) {
          return;
        }

        subscription = s;
        setPushEnabled();
      }).catch(function(err) {
        console.warn('Error during getSubscription()', err);
      });
  });
}

// Subscribes to the push service.
function subscribe() {
  var toggleButton = document.querySelector('.toggle-push-button');
  toggleButton.disabled = true;

  navigator.serviceWorker.ready.then(function(serviceWorkerRegistration) {
    serviceWorkerRegistration.pushManager.subscribe({userVisibleOnly: true}).then(function(s) {
        setPushEnabled();
        toggleButton.disabled = false;
        subscription = s
      }).catch(function(e) {
        if (Notification.permission === 'denied') {
          console.warn('Permission for Notifications was denied');
          toggleButton.disabled = true;
        } else {
          console.error('Unable to subscribe to push.', e);
          toggleButton.disabled = false;
          setPushDisabled();
        }
      });
  });
}

// Unsubscribes from the push service.
function unsubscribe() {
  var toggleButton = document.querySelector('.toggle-push-button');
  toggleButton.disabled = true;

  navigator.serviceWorker.ready.then(function(serviceWorkerRegistration) {
    serviceWorkerRegistration.pushManager.getSubscription().then(
      function(pushSubscription) {
        if (!pushSubscription) {
          toggleButton.disabled = false;
          setPushDisabled();
          return;
        }

        pushSubscription.unsubscribe().then(function(successful) {
          toggleButton.disabled = false;
          setPushDisabled();
        }).catch(function(e) {
          console.log('Unsubscription error: ', e);
          setPushDisabled();
        });
      }).catch(function(e) {
        console.error('Error thrown while unsubscribing from push messaging.', e);
      });
  });
}

function sendPush(text) {
  // You should send these values to the server once (when subscribing) and store them
  // there. They are needed to encrypt the messages.
  var data = new FormData();
  data.append('payload', text);
  data.append('endpoint', subscription.endpoint);
  data.append('p256dh', toBase64Url(subscription.getKey('p256dh')));
  data.append('auth', toBase64Url(subscription.getKey('auth')));

  fetch('./send-push/', {
    method: 'post',
    body: data
  })
  .catch(function (error) {
    console.error(error);
  });
}

// Updates the UI when push is enabled.
function setPushEnabled() {
  var toggleButton = document.querySelector('.toggle-push-button');
  toggleButton.textContent = 'Disable Push Messages';
  isPushEnabled = true;

  var pushButton = document.querySelector('.send-push-button');
  pushButton.disabled = false;
  pushButton.textContent = 'Send me a Message';
}

// Updates the UI when push is disabled or unavailable.
function setPushDisabled() {
  var toggleButton = document.querySelector('.toggle-push-button');
  toggleButton.textContent = 'Enable Push Messages';
  isPushEnabled = false;

  var pushButton = document.querySelector('.send-push-button');
  pushButton.disabled = true;
  pushButton.textContent = 'Enable Push First';
}

function toBase64Url(arrayBuffer) {
  var buffer = new Uint8Array(arrayBuffer.slice(0, arrayBuffer.byteLength));
  return btoa(String.fromCharCode.apply(null, buffer));
}

window.addEventListener('load', function() {
  var toggleButton = document.querySelector('.toggle-push-button');
  toggleButton.addEventListener('click', function() {
    if (isPushEnabled) {
      unsubscribe();
    } else {
      subscribe();
    }
  }, false);

  var sendButton = document.querySelector('.send-push-button');
  sendButton.addEventListener('click', function(event) {
    sendPush(document.querySelector('.push-payload').value);
  }, false);

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./service-worker.js').then(initialise);
  } else {
    console.warn('Service workers aren\'t supported in this browser.');
  }
});
