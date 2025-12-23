document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("form[data-single-submit]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      const submit = form.querySelector("button[type=submit]");
      if (submit && submit.dataset.submitting === "true") {
        event.preventDefault();
        return false;
      }
      if (submit) {
        submit.dataset.submitting = "true";
        submit.classList.add("disabled");
      }
    });
  });
});
