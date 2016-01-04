self.addEventListener('push', function(event) {
  var message = 'No payload';

  if (event.data.text())
    message = event.data.text();

  event.waitUntil(
    registration.showNotification('Go Web Push', {
      body: message
    })
  );
});
