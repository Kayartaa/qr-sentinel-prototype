const qrisDataMapping = {
    "00020101021126750023COM.BANKSUMSELBABEL.WWW01189360012001201481730215BSB0100000481730303UMI51440014ID.CO.QRIS.WWW0215ID10221613974200303UMI5204931153033605802ID5915DINAS PERIKANAN6014BELITUNG TIMUR61053351262070703A01630484BA": {
        entity: "Dinas Perikanan Kabupaten Belitung Timur",
        type: "QRIS",
        status: "VALID",
        notes: "QRIS sah untuk pembayaran instansi pemerintah daerah."
    },
    "00020101021126570011ID.DANA.WWW011893600915322828596602092282859660303UMI51440014ID.CO.QRIS.WWW0215ID10221507974320303UMI5204899953033605802ID5915NCP Asuransi Ku6015Kota Jakarta Ut61051425063049F24": {
        entity: "NCP Asuransi Ku",
        type: "QRIS",
        status: "VALID",
        notes: "Terlihat sebagai QRIS yang valid untuk entitas asuransi."
    },
    "00020101021226580013ID.CO.BRI.WWW01189360000200700826970208700826970303UMI51440014ID.CO.QRIS.WWW0215ID10253854300340303UMI520452115303360540732018185502025605799125802ID5924PENGEMBALIAN-DANA-TIKTOK6013JAKARTA PUSAT61051012062070703A0163040E1F": {
        entity: "PENGEMBALIAN-DANA-TIKTOK",
        type: "QRIS",
        status: "MALICIOUS",
        notes: "Diduga QRIS phishing. Sering digunakan dalam penipuan 'paket tertukar' atau 'pengembalian dana'."
    },
    "00020101021126660014ID.LINKAJA.WWW011893600911002162700102151802110116270010303UME51440014ID.CO.QRIS.WWW02151802110116270010303UME5204111153033605802ID5916RESTORASI MASJID6005MEDAN61052015362400716377B6EAF-F97B-41981602126281165802586304A749": {
        entity: "RESTORASI MASJID",
        type: "QRIS",
        status: "MALICIOUS",
        notes: "Umumnya digunakan dalam penipuan amal palsu untuk masjid atau donasi."
    }
};

const urlDataMapping = {
    "shopee.co.id": {
        entity: "shopee.co.id",
        type: "URL",
        status: "SECURE",
        notes: "Domain resmi dan aman untuk Shopee Indonesia."
    },
    "http://bit.ly/shopeebigsale662": {
        entity: "bit.ly/shopeebigsale662",
        type: "URL",
        status: "MALICIOUS",
        notes: "URL singkat yang sering digunakan untuk phishing atau pengalihan berbahaya. Tampaknya promosi Shopee palsu."
    }
};

function isValidUrl(str) {
    try {
        const url = new URL(str);
        return url.protocol === "http:" || url.protocol === "https:";
    } catch (e) {
        return false;
    }
}

function extractQrisMerchantName(qrisString) {
    const match = qrisString.match(/59(\d{2})([^0-9]{1,})/);
    if (match && match[1] && match[2]) {
        const length = parseInt(match[1], 10);
        if (match[2].length === length) {
             return match[2];
        } else {
            const startIndex = qrisString.indexOf("59" + match[1]) + 4;
            const merchantName = qrisString.substring(startIndex, startIndex + length);
            return merchantName;
        }
    }
    return "Tidak Ditemukan";
}

function analyzeAndDetect(inputData) {
    const processedInput = inputData.trim();
    
    if (isValidUrl(processedInput) || processedInput.includes("bit.ly")) {
        let foundUrl = null;
        for (const key in urlDataMapping) {
            if (processedInput.includes(key)) {
                foundUrl = urlDataMapping[key];
                break;
            }
        }
        if (foundUrl) {
            return foundUrl;
        } else {
            const entityName = (isValidUrl(processedInput) ? new URL(processedInput).hostname : processedInput) || processedInput;
            return {
                entity: entityName,
                type: "URL",
                status: "UNKNOWN",
                notes: "URL tidak ada di database dummy. Perlu analisis lebih lanjut (misalnya, cek reputasi, scan konten)."
            };
        }
    }
    else if (processedInput.startsWith("000201") && processedInput.includes("ID.CO.QRIS.WWW")) {
        const foundQris = qrisDataMapping[processedInput];
        if (foundQris) {
            return foundQris;
        } else {
            const merchantName = extractQrisMerchantName(processedInput);
            return {
                entity: merchantName,
                type: "QRIS",
                status: "UNKNOWN",
                notes: "Data QRIS tidak ada di database dummy. Validasi lebih lanjut (misalnya, checksum, verifikasi merchant) diperlukan."
            };
        }
    } else {
        return {
            entity: "N/A",
            type: "UNKNOWN",
            status: "UNKNOWN",
            notes: "Format input tidak dikenali sebagai URL standar atau string QRIS."
        };
    }
}

function displayResult(result, outputDiv) {
    let statusClass = '';
    let statusDisplay = result.status;

    if (result.status === "MALICIOUS") {
        statusClass = "malicious";
        statusDisplay = " BERBAHAYA ";
    } else if (result.status === "VALID") {
        statusClass = "valid";
        statusDisplay = " VALID ";
    } else if (result.status === "SECURE") {
        statusClass = "secure";
        statusDisplay = " AMAN ";
    } else {
        statusClass = "unknown";
        statusDisplay = " TIDAK DIKETAHUI ";
    }

    outputDiv.className = `result-card ${statusClass}`;
    outputDiv.innerHTML = `
        <p><strong>Tipe Terdeteksi:</strong> ${result.type}</p>
        <p><strong>Entitas/Domain:</strong> ${result.entity}</p>
        <p><strong>Status:</strong> <span style="font-size: 1.2em;">${statusDisplay}</span></p>
        <p><strong>Catatan:</strong> ${result.notes}</p>
    `;
}

const video = document.getElementById('camera-feed');
const resultOutputDiv = document.getElementById('resultOutput');
const canvas = document.createElement('canvas');
const context = canvas.getContext('2d');
let scanning = false;

async function startScanner() {
    if (scanning) return;
    try {
        resultOutputDiv.innerHTML = '<p class="placeholder">Memuat kamera...</p>';
        resultOutputDiv.className = 'result-card unknown';

        const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
        video.srcObject = stream;
        video.setAttribute('playsinline', true);
        video.play();
        scanning = true;
        
        setTimeout(() => tick(), 200);
    } catch (err) {
        console.error("Error accessing camera: ", err);
        resultOutputDiv.innerHTML = '<p class="placeholder">Gagal mengakses kamera. Mohon berikan izin.</p>';
        resultOutputDiv.className = 'result-card malicious';
    }
}

function stopScanner() {
    if (video.srcObject) {
        video.srcObject.getTracks().forEach(track => track.stop());
    }
    scanning = false;
}

function tick() {
    if (!scanning || !video.srcObject) {
        return;
    }

    canvas.height = video.videoHeight;
    canvas.width = video.videoWidth;
    context.drawImage(video, 0, 0, canvas.width, canvas.height);

    const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: "dontInvert",
    });

    if (code) {
        stopScanner();
        resultOutputDiv.innerHTML = '<p class="placeholder">Menganalisis...</p>';
        resultOutputDiv.className = 'result-card unknown';
        
        setTimeout(() => {
            const result = analyzeAndDetect(code.data);
            displayResult(result, resultOutputDiv);
        }, 500); 
    } else {
        requestAnimationFrame(tick);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    startScanner();
});