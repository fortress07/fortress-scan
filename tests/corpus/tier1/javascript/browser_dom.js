function renderGreeting() {
  const params = new URLSearchParams(location.search);
  const name = params.get('name');
  document.getElementById('greeting').innerHTML = 'Hi ' + name; // fsb-expect: FSB-XSS-001
}

function renderGreetingSafe() {
  const params = new URLSearchParams(location.search);
  document.getElementById('greeting').textContent = 'Hi ' + params.get('name');
}

function renderFromHash() {
  const fragment = decodeURIComponent(location.hash.slice(1));
  document.write('<h1>' + fragment + '</h1>'); // fsb-expect: FSB-XSS-001
}

function renderSanitized() {
  const fragment = location.hash.slice(1);
  document.getElementById('out').innerHTML = DOMPurify.sanitize(fragment);
}

window.addEventListener('message', (event) => {
  setTimeout(event.data, 10); // fsb-expect: FSB-EXEC-001
});
