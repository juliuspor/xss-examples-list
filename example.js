/**
 * 
 * SOURCES:
 * - jQuery .data() reads
 * - jQuery .attr()/.prop() reads
 * - jQuery .text() reads
 * - jQuery .html() reads
 * - dataset field access
 * - AJAX response data
 * - jQuery .val() reads
 * - Form attribute reads
 * 
 * SINKS:
 * - innerHTML/outerHTML assignments
 * - jQuery .html() writes
 * - jQuery .replaceWith()
 * - eval()
 * - document.write()/writeln()
 * - Event handler attributes (onclick, onload, etc.)
 * - Dangerous attributes (href, src, action)
 */

// ============================================================================
// PATTERN 1: jQuery .data() -> innerHTML
// ============================================================================
function vulnerableDataToInnerHTML() {
    const userInput = $('#user-input').data('value');
    document.getElementById('output').innerHTML = userInput;  // SINK: innerHTML
}

// ============================================================================
// PATTERN 2: jQuery .data(key) -> jQuery .html()
// ============================================================================
function vulnerableDataKeyToHtml() {
    const userData = $(this).data('user-content');
    $('#result').html(userData);  // SINK: jQuery html() write
}

// ============================================================================
// PATTERN 3: jQuery .attr() read -> outerHTML
// ============================================================================
function vulnerableAttrToOuterHTML() {
    const linkUrl = $('#malicious-link').attr('data-url');
    document.getElementById('container').outerHTML = linkUrl;  // SINK: outerHTML
}

// ============================================================================
// PATTERN 4: jQuery .prop() read -> jQuery .html()
// ============================================================================
function vulnerablePropToHtml() {
    const propValue = $('input').prop('value');
    $('.output').html(propValue);  // SINK: jQuery html()
}

// ============================================================================
// PATTERN 5: jQuery .text() read -> innerHTML
// ============================================================================
function vulnerableTextToInnerHTML() {
    const textContent = $('#source').text();
    document.getElementById('target').innerHTML = textContent;  // SINK: innerHTML
}

// ============================================================================
// PATTERN 6: jQuery .html() read -> jQuery .replaceWith()
// ============================================================================
function vulnerableHtmlToReplaceWith() {
    const htmlContent = $('.source-element').html();
    $('#target-element').replaceWith(htmlContent);  // SINK: replaceWith()
}

// ============================================================================
// PATTERN 7: dataset field access -> innerHTML
// ============================================================================
function vulnerableDatasetToInnerHTML() {
    const element = document.getElementById('user-card');
    const userName = element.dataset.username;
    document.getElementById('greeting').innerHTML = 'Hello ' + userName;  // SINK: innerHTML
}

// ============================================================================
// PATTERN 8: dataset field access -> eval()
// ============================================================================
function vulnerableDatasetToEval() {
    const scriptElement = document.getElementById('dynamic-script');
    const code = scriptElement.dataset.code;
    eval(code);  // SINK: eval()
}

// ============================================================================
// PATTERN 9: AJAX responseText -> document.write()
// ============================================================================
function vulnerableResponseTextToWrite() {
    const xhr = new XMLHttpRequest();
    xhr.onload = function() {
        const response = xhr.responseText;
        document.write(response);  // SINK: document.write()
    };
    xhr.open('GET', '/api/data');
    xhr.send();
}

// ============================================================================
// PATTERN 10: AJAX responseJSON -> document.writeln()
// ============================================================================
function vulnerableResponseJSONToWriteln() {
    fetch('/api/user')
        .then(response => response.json())
        .then(data => {
            const userHtml = data.responseJSON.html;
            document.writeln(userHtml);  // SINK: document.writeln()
        });
}

// ============================================================================
// PATTERN 11: config.data field access -> innerHTML
// ============================================================================
function vulnerableConfigDataToInnerHTML(config) {
    const configValue = config.data.userInput;
    document.getElementById('output').innerHTML = configValue;  // SINK: innerHTML
}

// ============================================================================
// PATTERN 12: jQuery .val() -> jQuery .html()
// ============================================================================
function vulnerableValToHtml() {
    const inputValue = $('#user-field').val();
    $('#display').html(inputValue);  // SINK: jQuery html()
}

// ============================================================================
// PATTERN 13: form.attr() read -> .attr() write with onclick
// ============================================================================
function vulnerableFormAttrToOnclick() {
    const formData = $('form').attr('data-action');
    $('#button').attr('onclick', formData);  // SINK: onclick attribute
}

// ============================================================================
// PATTERN 14: jQuery .data() -> .attr() write with onload
// ============================================================================
function vulnerableDataToOnload() {
    const imageCode = $('#img-source').data('onload-handler');
    $('img').attr('onload', imageCode);  // SINK: onload attribute
}

// ============================================================================
// PATTERN 15: dataset -> .prop() write with onerror
// ============================================================================
function vulnerableDatasetToOnerror() {
    const errorHandler = document.getElementById('config').dataset.errorHandler;
    $('img').prop('onerror', errorHandler);  // SINK: onerror attribute
}

// ============================================================================
// PATTERN 16: jQuery .data() -> .attr() write with href
// ============================================================================
function vulnerableDataToHref() {
    const userUrl = $('#link-data').data('url');
    $('a').attr('href', userUrl);  // SINK: href attribute (javascript: protocol possible)
}

// ============================================================================
// PATTERN 17: responseText -> .prop() write with src
// ============================================================================
function vulnerableResponseToSrc() {
    const xhr = new XMLHttpRequest();
    xhr.onload = function() {
        const scriptUrl = xhr.responseText;
        $('script').prop('src', scriptUrl);  // SINK: src attribute
    };
    xhr.open('GET', '/api/script-url');
    xhr.send();
}

// ============================================================================
// PATTERN 18: jQuery .val() -> .attr() write with action
// ============================================================================
function vulnerableValToAction() {
    const formAction = $('#action-input').val();
    $('form').attr('action', formAction);  // SINK: action attribute
}

// ============================================================================
// PATTERN 19: dataset -> .attr() write with onmouseover
// ============================================================================
function vulnerableDatasetToOnmouseover() {
    const hoverScript = document.getElementById('hover-config').dataset.script;
    $('#button').attr('onmouseover', hoverScript);  // SINK: onmouseover attribute
}

// ============================================================================
// PATTERN 20: jQuery .text() -> .prop() write with onfocus
// ============================================================================
function vulnerableTextToOnfocus() {
    const focusHandler = $('#focus-data').text();
    $('input').prop('onfocus', focusHandler);  // SINK: onfocus attribute
}

// ============================================================================
// PATTERN 21: Multiple sources combined -> innerHTML
// ============================================================================
function vulnerableMultipleSources() {
    const data1 = $('#input1').data('value');
    const data2 = $('input').val();
    const data3 = document.getElementById('config').dataset.extra;
    
    const combined = data1 + data2 + data3;
    document.getElementById('result').innerHTML = combined;  // SINK: innerHTML
}

// ============================================================================
// PATTERN 22: jQuery chaining -> jQuery .html()
// ============================================================================
function vulnerableChaining() {
    const content = $('#source').data('content');
    $('#target').parent().find('.output').html(content);  // SINK: jQuery html()
}

// ============================================================================
// Event handlers that trigger vulnerabilities
// ============================================================================
$(document).ready(function() {
    // Trigger on button click
    $('#process-data').on('click', function() {
        const userInput = $(this).data('user-input');
        $('#output').html(userInput);  // SINK: jQuery html()
    });
    
    // Trigger on form submit
    $('form').on('submit', function(e) {
        e.preventDefault();
        const formValue = $(this).find('input').val();
        document.getElementById('result').innerHTML = formValue;  // SINK: innerHTML
    });
    
    // Trigger on AJAX complete
    $.ajax({
        url: '/api/content',
        success: function(response) {
            const html = response.html;
            $('.container').html(html);  // SINK: jQuery html()
        }
    });
});

// ============================================================================
// SAFE PATTERNS (with sanitization) - These should NOT be detected
// ============================================================================
function safePatternWithSanitization() {
    const userInput = $('#user-input').data('value');
    const sanitized = XSS.sanitizeHtml(userInput);  // Sanitizer
    document.getElementById('output').innerHTML = sanitized;
}

function safePatternWithCustomSanitizer() {
    const userData = $(this).data('user-content');
    const clean = sanitizeHtml(userData);  // Sanitizer
    $('#result').html(clean);
}

function safePatternWithXSSGetValue() {
    const rawValue = $('#field').val();
    const safe = XSS.getXSSValue(rawValue);  // Sanitizer
    $('.output').html(safe);
}

