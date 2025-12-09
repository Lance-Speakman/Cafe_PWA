// Read details stored before redirect
const name = localStorage.getItem("lastOrderName") || "our customer";
const time = localStorage.getItem("lastOrderTime") || "your chosen time";

const msg = `Thanks for your order, ${name}! It will be ready for collection at ${time}.`;
document.getElementById("thanks-message").textContent = msg;