/**
 * Image processing utilities for profile pictures and banners.
 */

export const getImage = (file) => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (event) => resolve(event.target.result);
    reader.onerror = (error) => reject(error);
    reader.readAsDataURL(file);
  });
};

export const createImage = (url) => {
  return new Promise((resolve, reject) => {
    const image = new Image();
    image.addEventListener('load', () => resolve(image));
    image.addEventListener('error', (error) => reject(error));
    image.src = url;
  });
};

export const getCroppedImg = async (imageSrc, pixelCrop) => {
  const image = await createImage(imageSrc);
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  
  if (!ctx) {
    throw new Error('No 2d context');
  }

  // Set canvas size to the cropped size
  canvas.width = pixelCrop.width;
  canvas.height = pixelCrop.height;

  // Draw the cropped image onto the canvas
  ctx.drawImage(
    image,
    pixelCrop.x,
    pixelCrop.y,
    pixelCrop.width,
    pixelCrop.height,
    0,
    0,
    pixelCrop.width,
    pixelCrop.height
  );

  // Return as a blob
  return new Promise((resolve) => {
    canvas.toBlob(
      (blob) => {
        if (!blob) {
          console.error('Canvas is empty');
          return;
        }
        blob.name = 'cropped.jpg';
        resolve(URL.createObjectURL(blob));
      },
      'image/jpeg',
      0.9 // Quality
    );
  });
};

/**
 * Resizes an image to the specified dimensions while maintaining aspect ratio.
 * @param {string} src - The source image URL or data URL
 * @param {number} maxWidth - Maximum width in pixels
 * @param {number} maxHeight - Maximum height in pixels
 * @returns {Promise<string>} A promise that resolves with the resized image as a data URL
 */
export const resizeImage = (src, maxWidth, maxHeight) => {
  return new Promise((resolve) => {
    const img = new Image();
    img.src = src;
    
    img.onload = () => {
      const canvas = document.createElement('canvas');
      let width = img.width;
      let height = img.height;

      // Calculate new dimensions while maintaining aspect ratio
      if (width > height) {
        if (width > maxWidth) {
          height *= maxWidth / width;
          width = maxWidth;
        }
      } else {
        if (height > maxHeight) {
          width *= maxHeight / height;
          height = maxHeight;
        }
      }

      // Set canvas dimensions
      canvas.width = width;
      canvas.height = height;

      // Draw and resize image
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0, width, height);

      // Convert to data URL
      resolve(canvas.toDataURL('image/jpeg', 0.9));
    };
  });
};

/**
 * Converts a data URL to a File object
 * @param {string} dataUrl - The data URL to convert
 * @param {string} filename - The filename for the resulting file
 * @returns {Promise<File>} A promise that resolves with the File object
 */
export const dataUrlToFile = async (dataUrl, filename) => {
  const res = await fetch(dataUrl);
  const blob = await res.blob();
  return new File([blob], filename, { type: 'image/jpeg' });
};
