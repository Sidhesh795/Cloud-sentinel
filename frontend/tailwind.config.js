export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        sentinel: {
          bg: "#07111f",
          panel: "#0c1728",
          panel2: "#101d31",
          border: "#1e3554",
          cyan: "#38bdf8",
          blue: "#60a5fa",
          muted: "#90a4bd"
        }
      },
      boxShadow: {
        panel: "0 18px 60px rgba(0, 0, 0, 0.28)"
      }
    }
  },
  plugins: []
};
