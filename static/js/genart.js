const colors = {
    "red": "#CD0000",
    "black": "#000000",
    "whiteSmoke": "#F5F5F5",
    "darkRed": "#8B0000",
    "lightRed": "#FF4500",
}

let arcSize = 150;
let yStep = 10;
let padding = arcSize * 4;  // increased padding
let phi = 0;
let phiIncrement = 3;

let rotation = 0;

function setup() {
    //const canvaContainer = select("#landing-canva");
    //const canva = createCanvas(canvaContainer.width, canvaContainer.height);
    const canva = createCanvas(windowWidth, windowHeight);
    canva.parent("landing-canva");
    frameRate(15);

    // random vars
    rotation = random(PI / 2);
    arcSize = random(50, 150);
    yStep = random(5, 10);
    phiIncrement = random(1, 5);
    padding = arcSize * 4; // adjust padding based on arc size
}

function windowResized() {
    resizeCanvas(windowWidth, windowHeight);
    padding = arcSize * 4;
}

function draw() {
    background(colors.black);
    noFill();
    stroke(colors.red);

    // random rotation + translate with increased padding for more coverage
    push();
    rotate(rotation);
    translate(-padding * 2, -(Math.sin(rotation) * width) - padding * 2);

    for (let y = -padding * 3; y < (height + padding * 6); y += yStep) {

        let sw1 = map(sin(radians(y + phi)), -1, 1, 2, yStep);
        strokeWeight(sw1)
        for (let x1 = -padding * 3; x1 < width + padding * 6; x1 += arcSize * 2) {
            arc(x1, y, arcSize, arcSize, 0, PI);
        }

        let sw2 = map(sin(radians(y - phi)), -1, 1, 2, yStep);
        strokeWeight(sw2)
        for (let x2 = -padding * 3; x2 < width + padding * 6; x2 += arcSize * 2) {
            arc(x2 + arcSize, y, arcSize, arcSize, PI, TWO_PI);
        }
    }
    pop();
    phi = phi + phiIncrement;
}