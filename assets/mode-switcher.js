const toggleSwitch = document.getElementById('toggle'); 

const currentTheme = localStorage.getItem("theme");
if(currentTheme == 'dark'){      
  document.getElementsByTagName('body')[0].classList.toggle('dark');
      localStorage.getItem("theme","dark");
      toggleSwitch.checked = true
} else {
  document.getElementsByTagName('body')[0].classList.toggle('light');
}

  toggleSwitch.addEventListener("change", e => {
    if (e.target.checked) {
      document.getElementsByTagName('body')[0].classList.toggle('dark');
      localStorage.getItem("theme","dark");
      localStorage.setItem("theme","dark");
    } else {
      document.getElementsByTagName('body')[0].classList.remove('dark');
      localStorage.setItem("theme","light");
    }
  });
