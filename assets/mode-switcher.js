const toggleSwitch = document.getElementById('toggle'); 

const currentTheme = localStorage.getItem("theme") || null;

  if (currentTheme === 'dark') {
	document.body.classList.toggle('dark');
    toggleSwitch.checked = true
  }
  else {
    document.body.classList.toggle('light');
  }

  toggleSwitch.addEventListener("change", dark => {
    if (dark.target.checked) {
      localStorage.setItem("theme","dark");
      document.body.classList.toggle('dark');
      document.body.className = 'dark';
    } else {
      localStorage.setItem("theme","light");
      document.body.classList.toggle('light');
      document.body.className = 'light';
    }
  });
