I18n.defaultLocale = "en-US";
I18n.locale = "en-US";

I18n.translations = {};

fetch("/live2d-widget/i18n.json")
.then(res => res.json())
.then(data => {
    Object.keys(data).forEach(key => {
        console.log("key", key);
        I18n.translations[key] = data[key];
    })
});