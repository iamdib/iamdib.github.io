var toggleSwitch = document.getElementById('toggle'); 

var currentTheme = localStorage.getItem("theme");
if(currentTheme == 'dark'){      
  document.getElementsByTagName('body')[0].classList.add('dark');
  toggleSwitch.checked = true
} else {
  document.getElementsByTagName('body')[0].classList.remove('dark');
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
