const toggleSwitch = document.getElementById('toggle'); 

const currentTheme = localStorage.getItem("theme") || null;

  if (currentTheme === 'dark') {
	document.body.classList.toggle('dark');
    toggleSwitch.checked = true
  }
  else {
    document.body.classList.toggle('light');
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
