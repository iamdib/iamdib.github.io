var toggleSwitch = document.getElementById('toggle'); 	
var currentTheme = localStorage.getItem("theme");

if (currentTheme === 'dark') {
  document.body.classList.toggle('dark');
  toggleSwitch.checked = true
}
else {
  document.body.classList.toggle('light');
}

toggleSwitch.addEventListener("change", e => {
  if (e.target.checked) {
    document.body.classList.toggle('dark');
    document.body.className = 'dark';
    localStorage.setItem("theme","dark");
  } else {
    document.body.classList.toggle('light');
    document.body.className = 'light';
    localStorage.setItem("theme","light");
  }
});
