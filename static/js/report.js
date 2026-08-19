document.addEventListener("DOMContentLoaded", () => {
    const btn = document.getElementById("printBtn");
    if (btn) btn.addEventListener("click", () => window.print());
});
