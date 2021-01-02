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
      document.body.classList.toggle('dark');
      document.body.className = 'dark';
      localStorage.setItem("theme","dark");
    } else {
      document.body.classList.toggle('light');
      document.body.className = 'light';
      localStorage.setItem("theme","light");
    }
    const toggleSwitch = document.querySelector('#toggle input[type="checkbox"]');
		
		if (localStorage.theme) {
		  toggleSwitch.checked = localStorage.theme === "dark";
		}
		
		function switchTheme(e) {
		  const theme = e.target.checked ? "dark" : "light";
		  document.documentElement.setAttribute("theme", theme);
		  localStorage.theme = theme;
		}
		
		toggleSwitch.addEventListener("change", switchTheme);
  });
