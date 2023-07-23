const testimonials = document.querySelectorAll(".testimonial");
const leftArrow = document.querySelector(".left-arrow");
const rightArrow = document.querySelector(".right-arrow");
const contactForm = document.querySelector(".contact-form");
const form = document.querySelector("form");
contactForm.classList.add("show");
form.classList.add("show");

let currentSlide = 0;

function showTestimonial(slideIndex) {
  testimonials.forEach((testimonial, index) => {
    testimonial.classList.remove("active", "previous", "next");

    if (index === slideIndex) {
      testimonial.classList.add("active");
    } else if (
      index === slideIndex - 1 ||
      (slideIndex === 0 && index === testimonials.length - 1)
    ) {
      testimonial.classList.add("previous");
    } else if (
      index === slideIndex + 1 ||
      (slideIndex === testimonials.length - 1 && index === 0)
    ) {
      testimonial.classList.add("next");
    }
  });
}

leftArrow.addEventListener("click", () => {
  currentSlide =
    currentSlide === 0 ? testimonials.length - 1 : currentSlide - 1;
  showTestimonial(currentSlide);
});

rightArrow.addEventListener("click", () => {
  currentSlide =
    currentSlide === testimonials.length - 1 ? 0 : currentSlide + 1;
  showTestimonial(currentSlide);
});

showTestimonial(currentSlide);

function handleColorSchemeChange() {
  var colorScheme = window
    .getComputedStyle(document.documentElement)
    .getPropertyValue("--darkreader-neutral-background")
    ? "dark"
    : "light";

  var logoElements = document.getElementsByClassName("logo");

  for (var i = 0; i < logoElements.length; i++) {
    var logoElement = logoElements[i];

    if (colorScheme === "dark") {
      logoElement.classList.add("dark-mode");
    } else {
      logoElement.classList.remove("dark-mode");
    }
  }
}

// Initial update of the logo images based on the current color scheme
handleColorSchemeChange();

// Listen for changes in the color scheme preference
window.addEventListener("DarkReaderToggle", handleColorSchemeChange);

// JavaScript for the hamburger menu
document.addEventListener("DOMContentLoaded", function () {
  const hamburgerIcon = document.querySelector(".hamburger-icon");
  const menuBar = document.querySelector(".menu-bar");

  hamburgerIcon.addEventListener("click", function () {
    menuBar.classList.toggle("open"); // Toggle the 'open' class to show/hide the menu bar
  });
  // Close the menu when clicking outside the menu bar
  document.addEventListener("click", function (event) {
    const targetElement = event.target;
    if (
      !menuBar.contains(targetElement) &&
      !hamburgerIcon.contains(targetElement)
    ) {
      menuBar.classList.remove("open");
    }
  });
});

// JavaScript for updating the paragraph content without page reload
document.addEventListener("DOMContentLoaded", function () {
  const dynamicParagraph = document.querySelector(".dynamic-paragraph");

  // Function to update paragraph content based on screen width
  function updateParagraphContent() {
    const screenWidth = window.innerWidth;

    if (screenWidth >= 320 && screenWidth <= 576) {
      dynamicParagraph.textContent =
        "Introducing BrainSnap - your ultimate study companion! Access excellent resources, notes, and a user-friendly interface to maximize your academic potential. Join us now for the best study experience and achieve academic excellence!";
    } else {
      dynamicParagraph.textContent =
        "Introducing BrainSnap - the ultimate study companion for students! With our platform, you can say goodbye to the stress of finding excellent resources and notes for your studies. We provide a one-stop-shop for all your academic needs, ensuring you have access to the best resources available. Our user-friendly interface is designed to help you study with ease and efficiency, allowing you to maximize your potential and achieve academic success. So why choose BrainSnap? Because we understand the importance of education and are committed to providing you with the best study experience possible. Join us now and take the first step towards academic excellence!";
    }
  }

  // Call the function initially
  updateParagraphContent();

  // Add event listener for window resize to dynamically update the content
  window.addEventListener("resize", updateParagraphContent);
});

// JavaScript to handle visibility on hover
const dropdownContainer = document.querySelector(".dropdown");

document.querySelector(".profile").addEventListener("mouseenter", () => {
  dropdownContainer.style.display = "block";
});

document.querySelector(".profile").addEventListener("mouseleave", () => {
  dropdownContainer.style.display = "none";
});
