(function () {
  "use strict";
  const data = JSON.parse(document.getElementById("scan-data").textContent);
  document.getElementById("result").replaceChildren(window.SecureQR.renderResult(data));
})();
