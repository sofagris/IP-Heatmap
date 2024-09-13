// static/js/modals.js

// Function to open the attacker modal
function openAttackerModal() {
    document.getElementById('attacker-modal').style.display = 'block';
}

// Function to close the attacker modal
document.getElementById('close-attacker-modal').onclick = function() {
    document.getElementById('attacker-modal').style.display = 'none';
};

// Function to close the client modal
document.getElementById('close-client-modal').addEventListener('click', function() {
    document.getElementById('client-modal').style.display = 'none';
});

// Function to switch between tabs
function openTab(evt, tabName) {
    var i, tabcontent, tablinks;
    
    // Hide all tab contents
    tabcontent = document.getElementsByClassName("tabcontent");
    for (i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.display = "none";
    }

    // Remove the active class from all buttons
    tablinks = document.getElementsByClassName("tablinks");
    for (i = 0; i < tablinks.length; i++) {
        tablinks[i].classList.remove("active");
    }

    // Show the current tab and add active class to the button
    document.getElementById(tabName).style.display = "block";
    evt.currentTarget.classList.add("active");
}

// Default to open the Overview tab
document.addEventListener('DOMContentLoaded', function () {
    document.getElementsByClassName("tablinks")[0].click();
});
