import * as cocoSsd from '@tensorflow-models/coco-ssd';
import * as tf from '@tensorflow/tfjs';

export class ComputerVisionService {
  constructor() {
    this.model = null;
    this.isModelLoading = false;
    this.objectDetectionInterval = null;
    this.detectionCallback = null;
    this.lastDetectionTime = 0;
    this.detectionInterval = 1000; // ms between detections
  }

  async loadModel() {
    if (this.model) return this.model;
    
    this.isModelLoading = true;
    try {
      // Load the COCO-SSD model
      this.model = await cocoSsd.load({
        base: 'lite_mobilenet_v2', // Smaller, faster model
      });
      console.log('Computer Vision model loaded');
      this.isModelLoading = false;
      return this.model;
    } catch (error) {
      console.error('Failed to load computer vision model:', error);
      this.isModelLoading = false;
      throw error;
    }
  }

  async detectObjects(videoElement) {
    if (!this.model) {
      await this.loadModel();
    }

    try {
      // Run object detection
      const predictions = await this.model.detect(videoElement);
      
      // Filter out low confidence predictions
      const highConfidencePredictions = predictions.filter(
        prediction => prediction.score > 0.5
      );
      
      return highConfidencePredictions;
    } catch (error) {
      console.error('Error during object detection:', error);
      return [];
    }
  }

  startObjectDetection(videoElement, callback) {
    this.stopObjectDetection();
    this.detectionCallback = callback;
    
    this.objectDetectionInterval = setInterval(async () => {
      if (Date.now() - this.lastDetectionTime < this.detectionInterval) {
        return;
      }
      
      try {
        const predictions = await this.detectObjects(videoElement);
        this.lastDetectionTime = Date.now();
        
        if (this.detectionCallback && predictions.length > 0) {
          this.detectionCallback(predictions);
        }
      } catch (error) {
        console.error('Error in object detection loop:', error);
      }
    }, 300); // Check every 300ms, but actual detection rate is controlled by detectionInterval
  }

  stopObjectDetection() {
    if (this.objectDetectionInterval) {
      clearInterval(this.objectDetectionInterval);
      this.objectDetectionInterval = null;
    }
    this.detectionCallback = null;
  }

  // Analyze detected objects and generate a natural language description
  generateObjectDescription(predictions) {
    if (!predictions || predictions.length === 0) {
      return "I don't see any objects at the moment.";
    }

    // Group objects by class
    const objectCounts = {};
    predictions.forEach(prediction => {
      objectCounts[prediction.class] = (objectCounts[prediction.class] || 0) + 1;
    });

    // Generate description
    const objectDescriptions = [];
    for (const [objectName, count] of Object.entries(objectCounts)) {
      const article = ['a', 'e', 'i', 'o', 'u'].includes(objectName[0].toLowerCase()) ? 'an' : 'a';
      objectDescriptions.push(
        count > 1 
          ? `${count} ${objectName}s` 
          : `${article} ${objectName}`
      );
    }

    let description = "I can see ";
    if (objectDescriptions.length === 1) {
      description += objectDescriptions[0];
    } else {
      const last = objectDescriptions.pop();
      description += `${objectDescriptions.join(', ')} and ${last}`;
    }

    // Add position information for the most prominent object
    if (predictions.length > 0) {
      const mainObject = predictions[0];
      const x = mainObject.bbox[0] + mainObject.bbox[2] / 2;
      const y = mainObject.bbox[1] + mainObject.bbox[3] / 2;
      
      let position = "";
      if (x < 0.3) position += "on the left ";
      else if (x > 0.7) position += "on the right ";
      
      if (y < 0.3) position += "at the top";
      else if (y > 0.7) position += "at the bottom";
      
      if (position) {
        description += `. The most prominent object is ${mainObject.class} ${position}.`;
      }
    }

    return description + ".";
  }

  // Clean up resources
  dispose() {
    this.stopObjectDetection();
    if (this.model) {
      tf.dispose(this.model);
      this.model = null;
    }
  }
}

export const computerVisionService = new ComputerVisionService();
