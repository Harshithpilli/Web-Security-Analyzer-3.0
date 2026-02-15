document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('urlInput');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const loadingDiv = document.getElementById('loading');
    const resultSection = document.getElementById('resultSection');
    const errorSection = document.getElementById('errorSection');
    const errorMessage = document.getElementById('errorMessage');
    const riskScore = document.getElementById('riskScore');
    const riskLevel = document.getElementById('riskLevel');
    const mlPrediction = document.getElementById('mlPrediction');
    const heuristicBody = document.getElementById('heuristicBody');
    const detailsList = document.getElementById('detailsList');
    const feedbackButtons = document.querySelectorAll('.feedback-btn');
    const feedbackStatus = document.getElementById('feedbackStatus');

    // Analyze button event listener
    analyzeBtn.addEventListener('click', analyzeUrl);

    // Also allow Enter key to trigger analysis
    urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            analyzeUrl();
        }
    });

    // Feedback buttons event listeners
    feedbackButtons.forEach(button => {
        button.addEventListener('click', function() {
            const label = parseInt(this.getAttribute('data-label'));
            provideFeedback(label);
        });
    });

    async function analyzeUrl() {
        const url = urlInput.value.trim();
        
        if (!url) {
            showError('Please enter a URL to analyze.');
            return;
        }

        // Show loading, hide results and errors
        showLoading();
        hideResults();
        hideError();

        try {
            const response = await fetch('/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: url })
            });

            const data = await response.json();

            if (data.success) {
                displayResults(data.data);
                showResults();
            } else {
                showError(data.error || 'An error occurred during analysis.');
            }
        } catch (error) {
            showError('Network error: ' + error.message);
        } finally {
            hideLoading();
        }
    }

    function displayResults(results) {
        // Display risk score and level
        riskScore.textContent = results.risk_score;
        
        // Set risk level styling based on score
        let levelClass = '';
        let levelText = '';
        if (results.risk_score >= 7) {
            levelClass = 'level-high';
            levelText = 'High Risk';
        } else if (results.risk_score >= 4) {
            levelClass = 'level-medium';
            levelText = 'Medium Risk';
        } else {
            levelClass = 'level-low';
            levelText = 'Low Risk';
        }
        
        riskLevel.textContent = levelText;
        riskLevel.className = levelClass;
        
        // Update score circle color based on risk level
        const scoreCircle = document.querySelector('.score-circle');
        scoreCircle.className = 'score-circle'; // Reset classes
        scoreCircle.classList.add(`score-${levelClass.split('-')[1]}`);

        // Display ML prediction
        let mlText = '';
        let mlClass = '';
        if (results.ml_prediction === 1) {
            mlText = '⚠️ Machine Learning Model: This URL is predicted to be MALICIOUS';
            mlClass = 'prediction-malicious';
        } else {
            mlText = '✅ Machine Learning Model: This URL is predicted to be SAFE';
            mlClass = 'prediction-benign';
        }
        
        mlPrediction.textContent = mlText;
        mlPrediction.className = `prediction ${mlClass}`;

        // Display heuristic checks
        heuristicBody.innerHTML = '';
        for (const [check, score] of Object.entries(results.heuristic_scores)) {
            const row = document.createElement('tr');
            
            // Format check name
            const checkName = check.charAt(0).toUpperCase() + check.slice(1).replace(/_/g, ' ');
            
            row.innerHTML = `
                <td>${checkName}</td>
                <td>${score}</td>
            `;
            heuristicBody.appendChild(row);
        }

        // Display security details
        detailsList.innerHTML = '';
        results.details.forEach(detail => {
            const li = document.createElement('li');
            li.textContent = detail;
            detailsList.appendChild(li);
        });
    }

    function provideFeedback(label) {
        const url = urlInput.value.trim();
        
        if (!url) {
            showFeedbackStatus('Please enter a URL first.', 'error');
            return;
        }

        // Disable buttons during submission
        feedbackButtons.forEach(btn => btn.disabled = true);

        fetch('/feedback', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                url: url,
                label: label
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showFeedbackStatus(
                    `Thank you for your feedback! The model has been updated to improve future predictions.`,
                    'success'
                );
            } else {
                showFeedbackStatus('Error submitting feedback: ' + (data.error || 'Unknown error'), 'error');
            }
        })
        .catch(error => {
            showFeedbackStatus('Network error: ' + error.message, 'error');
        })
        .finally(() => {
            // Re-enable buttons after a delay
            setTimeout(() => {
                feedbackButtons.forEach(btn => btn.disabled = false);
            }, 2000);
        });
    }

    function showLoading() {
        loadingDiv.classList.remove('hidden');
    }

    function hideLoading() {
        loadingDiv.classList.add('hidden');
    }

    function showResults() {
        resultSection.classList.remove('hidden');
    }

    function hideResults() {
        resultSection.classList.add('hidden');
    }

    function showError(message) {
        errorMessage.textContent = message;
        errorSection.classList.remove('hidden');
    }

    function hideError() {
        errorSection.classList.add('hidden');
    }

    function showFeedbackStatus(message, type) {
        feedbackStatus.textContent = message;
        feedbackStatus.className = `feedback-status ${type === 'success' ? 'feedback-success' : 'feedback-error'}`;
        feedbackStatus.classList.remove('hidden');
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            feedbackStatus.classList.add('hidden');
        }, 5000);
    }
});