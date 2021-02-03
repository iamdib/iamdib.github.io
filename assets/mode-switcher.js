var toggleSwitch = document.getElementById('toggle'); 

var currentTheme = localStorage.getItem("theme") || null;

  if (currentTheme === 'dark') {
    document.body.className = 'dark';
    toggleSwitch.checked = true
  }
  else {
    document.body.className = 'light';
  }

  toggleSwitch.addEventListener("change", e => {
    if (e.target.checked) {
      document.body.className = 'dark';
      localStorage.setItem("theme","dark");
    } else {
      document.body.className = 'light';
      localStorage.setItem("theme","light");
    }
  });
