document.getElementById("scanBtn").addEventListener("click", async () => {

  const [tab] = await chrome.tabs.query({
    active: true,
    currentWindow: true
  });

  const currentUrl = tab.url;

  const response = await fetch("http://127.0.0.1:8000/analyze", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      text: currentUrl
    })
  });

  const data = await response.json();

  const resultBox = document.getElementById("result");
  resultBox.style.display = "block";

  const level = document.getElementById("level");

  level.innerText = data.level;
  level.className = "";

  if (data.level === "HIGH RISK") {
    level.classList.add("high");
  } else if (data.level === "SUSPICIOUS") {
    level.classList.add("suspicious");
  } else {
    level.classList.add("low");
  }

  document.getElementById("score").innerText =
    data.score + "/100";

  document.getElementById("explanation").innerText =
    data.explanation;
});
