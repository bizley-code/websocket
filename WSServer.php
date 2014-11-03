<?php
/**
 * @author Paweł Bizley Brzozowski
 */
class WSServer
{
    protected $error;
    protected $started = false;
    protected $host;
    protected $port;
    protected $socket = null;
    protected $clients;

    public function getHost()
    {
        return $this->host;
    }
    
    public function setHost($value)
    {
        $this->host = $value;
        return $this;
    }
    
    public function getPort()
    {
        return $this->port;
    }
    
    public function setPort($value)
    {
        $this->port = $value;
        return $this;
    }
    
    public function __construct()
    {
        $this->setHost('localhost');
        $this->setPort(9000);
        $this->init();
    }
    
    public function init()
    {
        if ($this->socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP)) {
            $this->started = true;
            if ($this->setOptions()) {
                if ($this->bind()) {
                    $this->clients = [$this->socket];
                    
                    return true;
                }
            }
        }
        else {
            $this->error = 'CREATE_SOCKET_ERROR';
        }
        
        return false;
    }
    
    protected function setOptions()
    {
        if (socket_set_option($this->socket, SOL_SOCKET, SO_REUSEADDR, 1) === false) {
            return $this->setSocketError();
        }
        
        return true;
    }
    
    protected function setSocketError()
    {
        $this->error = socket_strerror(socket_last_error($this->socket));
        return false;
    }
    
    protected function bind()
    {
        if (socket_bind($this->socket, 0, $port) === false) {
            return $this->setSocketError();
        }
        
        return true;
    }
    
    protected function listen()
    {
        if (socket_listen($this->socket) === false) {
            return $this->setSocketError();
        }
        
        return true;
    }
    
    public function start()
    {
        if ($this->started) {
            if ($this->listen()) {
                $this->serve();
                socket_close($this->socket);
            }
        }
    }
    
    protected function serve()
    {
        $null = NULL;
    
	$changed = $this->clients;
        if (socket_select($changed, $null, $null, 0, 10) === false) {
            return $this->setSocketError();
        }
        else {
	
            if (in_array($this->socket, $changed)) {
		
                if (($socketNew = socket_accept($this->socket)) === false) {
                    return $this->setSocketError();
                }
                else {
                    $this->clients[] = $socketNew;
		
                    if (($header = socket_read($socketNew, 1024)) === false) {
                        return $this->setSocketError();
                    }
                    else {
                        if ($this->handshake($header, $socketNew) === false) {
                            return false;
                        }
                        else {
                            if (socket_getpeername($socketNew, $ip) === false) {
                                $this->error = 'GET_PEERNAME_SOCKET_ERROR';
                                return false;
                            }
                            else {
                                if ($this->sendMessage($this->mask(json_encode(['type' => 'system', 'message' => $ip . ' connected']))) === false) {
                                    return false;
                                }
                                else {
                                    $foundSocket = array_search($this->socket, $changed);
                                    unset($changed[$foundSocket]);
                                }
                            }
                        }
                    }
                }
            }
	}
	
	foreach ($changed as $changedSocket) {	
		
            while (socket_recv($changedSocket, $buffer, 1024, 0) >= 1) {
                
                $message        = json_decode($this->unmask($buffer));
                $userName       = $message->name;
                $userMessage    = $message->message;
                $userColor      = $message->color;

                if ($this->sendMessage($this->mask(json_encode(['type' => 'usermsg', 'name' => $userName, 'message' => $userMessage, 'color' => $userColor]))) === false) {
                    return false;
                }
                else {
                    break(2);
                }
            }
		
            $buffer = socket_read($changedSocket, 1024, PHP_NORMAL_READ);
            if ($buf === false) {
                    
                $foundSocket = array_search($changedSocket, $this->clients);
                if (socket_getpeername($changedSocket, $ip) === false) {
                    $this->error = 'GET_PEERNAME_SOCKET_ERROR';
                    return false;
                }
                else {
                    unset($this->clients[$foundSocket]);
                }

                if ($this->sendMessage($this->mask(json_encode(['type' => 'system', 'message' => $ip .' disconnected']))) === false) {
                    return false;
                }
            }
	}
        
        $this->serve();
    }
    
    protected function sendMessage($message)
    {
	foreach ($this->clients as $changedSocket) {
            if (socket_write($changedSocket, $message, strlen($message)) === false) {
                return $this->setSocketError();
            }
	}
        
	return true;
    }
    
    protected function mask($text)
    {
	$b1 = 0x80 | (0x1 & 0x0f);
	$length = strlen($text);
	
	if ($length <= 125) {
            $header = pack('CC', $b1, $length);
        }
	elseif ($length > 125 && $length < 65536) {
            $header = pack('CCn', $b1, 126, $length);
        }
	elseif ($length >= 65536) {
            $header = pack('CCNN', $b1, 127, $length);
        }
        
	return $header . $text;
}

    protected function unmask($text)
    {
	$length = ord($text[1]) & 127;
	
        if ($length == 126) {
            $masks = substr($text, 4, 4);
            $data = substr($text, 8);
	}
	elseif ($length == 127) {
            $masks = substr($text, 10, 4);
            $data = substr($text, 14);
	}
	else {
            $masks = substr($text, 2, 4);
            $data = substr($text, 6);
	}
	
        $text = "";
	for ($i = 0; $i < strlen($data); ++$i) {
            $text .= $data[$i] ^ $masks[$i % 4];
	}
	
        return $text;
    }
    
    protected function handshake($receivedHeader, $clientConnection)
    {
	$headers = [];
	$lines = preg_split("/\r\n/", $receivedHeader);
	
        foreach ($lines as $line) {
            if (preg_match('/\A(\S+): (.*)\z/', rtrim($line), $matches)) {
                $headers[$matches[1]] = $matches[2];
            }
	}

	$secKey     = $headers['Sec-WebSocket-Key'];
	$secAccept  = base64_encode(pack('H*', sha1($secKey . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));
	
	$upgrade    = "HTTP/1.1 101 Web Socket Protocol Handshake\r\n" .
	"Upgrade: websocket\r\n" .
	"Connection: Upgrade\r\n" .
	"WebSocket-Origin: " . $this->host . "\r\n" .
	"WebSocket-Location: ws://" . $this->host . ":" . $this->port . "\r\n".
	"Sec-WebSocket-Accept: $secAccept\r\n\r\n";
        
        if (socket_write($clientConnection, $upgrade, strlen($upgrade)) === false) {
            return $this->setSocketError();
        }
        
        return true;
    }
}