export const handleFileUpload = (file) => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      resolve({
        name: file.name,
        type: file.type,
        size: file.size,
        data: e.target.result,
        timestamp: new Date().toISOString()
      });
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
};

export const downloadFile = (fileData, fileName) => {
  const link = document.createElement('a');
  link.href = fileData.data;
  link.download = fileName || fileData.name;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
};
