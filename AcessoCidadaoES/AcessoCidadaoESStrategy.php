<?php

use Curl\Curl;
use MapasCulturais\App;
use MapasCulturais\Entities\User;

class AcessoCidadaoESStrategy extends OpauthStrategy
{

	/**
	 * Compulsory config keys, listed as unassociative arrays
	 */
	public $expects = [ 'auth_endpoint', 'token_endpoint', 'response_type', 'client_id', 'scope', 'redirect_uri', 'nonce', 'dic_agent_fields_update'];
	/**
	 * Optional config keys, without predefining any default values.
	 */
	public $optionals = ['register_form_action', 'register_form_method'];
	/**
	 * Optional config keys with respective default values, listed as associative arrays
	 * eg. array('scope' => 'email');
	 */
	public $defaults = ['redirect_uri' => '{complete_url_to_strategy}oauth2callback'];

	/**
	 * Auth request
	 * https://docs.developer.acessocidadao.es.gov.br/AutenticacaoUsuarios/ComoGerarToken/
	 */
	public function request()
	{
		$_SESSION['AcessoCidadaoES-state'] = md5($this->strategy['state_salt'].time());
		$_SESSION['AcessoCidadaoES-nonce'] = md5($this->strategy['nonce'].time());

		$url = $this->strategy['auth_endpoint'];
		$params = array(
			'response_type' => 'code id_token',
			'client_id' => $this->strategy['client_id'],
			'scope' => $this->strategy['scope'],
			'redirect_uri' => $this->strategy['redirect_uri'],
			'nonce' => $_SESSION['AcessoCidadaoES-nonce'],
			'state' => $_SESSION['AcessoCidadaoES-state'],
			'response_mode' => 'form_post',
			//'code_challenge' => $this->strategy['code_challenge'],
			//'code_challenge_method' => $this->strategy['code_challenge_method'],
		);

		foreach ($this->optionals as $key) {
			if (!empty($this->strategy[$key])) $params[$key] = $this->strategy[$key];
		}
		
		$this->clientGet($url, $params);
	}

	/**
	 * Internal callback, after OAuth
	 */
	public function oauth2callback()
	{
		// $app = App::i();
		// if(isset($app->config['app.log.auth']) && $app->config['app.log.auth']) {
		// 	$app->log->debug("===================\n".
		// 		 __METHOD__.
		// 		 "\n" . print_r('Entrou na funcao callback.', true) .
		// 		 "\n=================");
			// $app->log->debug("===================\n".
			// 	 __METHOD__.
			// 	 "\nConteúdo de \$_GET:\n" . print_r($_GET, true) .
			// 	 "\n=================");
			// $app->log->debug("===================\n".
			// 	 __METHOD__.
			// 	 "\nConteúdo de \$_POST:\n" . print_r($_POST, true) .
			// 	 "\n=================");
		// }

		//if ((array_key_exists('code', $_POST) && !empty($_POST['code'])) && (array_key_exists("state", $_POST) && $_POST['state'] == $_SESSION['AcessoCidadaoES-state'])) {
		if ((array_key_exists('code', $_POST) && !empty($_POST['code']))) {
			
			$code = $_POST['code'];
		
			$url = $this->strategy['token_endpoint'];

			$params = array(
				'grant_type' => 'authorization_code',
				'code' => $code,
				'redirect_uri' => $this->strategy['redirect_uri'],
			);

			$token = base64_encode("{$this->strategy['client_id']}:{$this->strategy['client_secret']}");
			$curl = new Curl;
			$curl->setHeader('Content-Type', 'application/x-www-form-urlencoded');
			$curl->setHeader('Authorization', "Basic {$token}");

			$app = App::i();      

			$curl->post($url, $params);
			$curl->close();
			$response = $curl->response;

			//$results = json_decode($response);
			$results=$response;

			if (!empty($results) && !empty($results->id_token) && !empty($results->access_token)) {

				/** @var stdClass $userinfo */
				$userinfo = $this->userinfo($results->id_token);
				$userinfo->access_token =  $results->access_token;
				//$userinfo->cpf =  $userinfo->sub;
				//$exp_name = explode(" ", $userinfo->name);
				
				// Decodificando o access_token
				$access_token_data = $this->decodeToken($results->access_token);

				if ($access_token_data) {
					// Adiciona as chaves do access_token diretamente ao userinfo
					foreach ($access_token_data as $key => $value) {
						$userinfo->$key = $value;
					}
				} else {
					// Trata o caso de um token inválido
					throw new Exception('Invalid access token format.');
				}

				$userinfoFromToken = $this->userinfoWithAccessToken($results->access_token);
				
				// Valida se os dados necessarios foram retornados
				if (!empty($userinfoFromToken)) {

					$info = [
						//'name' => $exp_name[0],
						'name' => $userinfoFromToken->apelido,
						'cpf' => $userinfoFromToken->cpf,
						'email' => $userinfoFromToken->email,
						//'full_name' => $userinfoFromToken->name,
						'full_name' => $userinfoFromToken->nome,
						'dic_agent_fields_update' => $this->strategy['dic_agent_fields_update']
					];
					
					$this->auth = array(
						'uid' => $userinfo->jti,
						'credentials' => array(
							'token' => $results->id_token,
							'expires' => $userinfo->exp
						),
						'raw' => $userinfo,
						'info' => $info,
						'applySeal' => $this->strategy['applySealId']
					);

					$this->callback();

				} else {
					$error = [
						'code' => 'userinfo_error',
						'message' => 'Failed to retrieve user information',
						'raw' => $results
					];
					$this->errorCallback($error);
				}
			} else {
				$error = array(
					'code' => 'access_token_error',
					'message' => 'Failed when attempting to obtain access token',
					'raw' => array(
						'response' => $response,
					)
				);
				$this->errorCallback($error);
			}
		} else {
			$error = array(
				'code' => 'oauth2callback_error',
				'raw' => $_GET
			);

			$this->errorCallback($error);
		}
	}

	/**
	 * @param string $id_token 
	 * @return array Parsed JSON results
	 */
	private function userinfo($id_token)
	{
		$exp = explode(".", $id_token);
		return json_decode(base64_decode($exp[1]));
	}

	/**
	 * Decodifica um token JWT para obter o payload.
	 *
	 * @param string $token O token a ser decodificado (id_token ou access_token)
	 * @return stdClass|false O payload decodificado como objeto ou false se não for um JWT válido
	 */
	private function decodeToken($token) {
		$parts = explode('.', $token);

		// Verifica se o token tem as três partes do JWT
		if (count($parts) !== 3) {
			return false;
		}

		// Decodifica o payload (segunda parte)
		$payload = base64_decode($parts[1], true);

		// Retorna o JSON decodificado como um objeto
		return $payload ? json_decode($payload) : false;
	}

	/**
	 * @param string $access_token
	 * @return array Parsed JSON results
	 */
	private function userinfoWithAccessToken($access_token) {
		$userinfo_endpoint = $this->strategy['userinfo_endpoint'];

		try {
			// Criando uma instância do Curl
			$curl = new Curl();

			// Configurando o cabeçalho Authorization
			$curl->setHeader('Authorization', 'Bearer ' . $access_token);

			// Realizando a requisição GET
			$curl->get($userinfo_endpoint);

			// Verificar se houve erro
			if ($curl->error) {
				$error = [
					'code' => 'curl_error',
					'message' => $curl->errorMessage,
					'raw' => [
						'response' => $curl->response,
						'http_code' => $curl->httpStatusCode
					]
				];
				$this->errorCallback($error);
			}

			// Retornar os dados decodificados
			//return json_decode($curl->response, true);
			return $curl->response;
		} catch (Exception $e) {
			// Captura exceções e as passa ao callback de erro
			$error = [
				'code' => 'exception',
				'message' => $e->getMessage(),
				'raw' => []
			];
			$this->errorCallback($error);
		} finally {
			// Fechar a instância do Curl
			if (isset($curl)) {
				$curl->close();
			}
		}
	}

	///**
	// * @param string $access_token
	// * @return array Parsed JSON results
	// */
	//private function userinfoWithAccessToken($access_token){
	//	$headers = array(
	//		'Authorization' => 'Bearer ' . $access_token
	//	);
	//
	//	// Realizando a requisição GET para o endpoint userinfo
	//	$userinfo = $this->serverGet($this->strategy['userinfo_endpoint'], array(), null, $headers);
	//
	//	// Verificando se obteve uma resposta
	//	if (!empty($userinfo)) {
	//		// Retornando o objeto de dados do usuário (decodificando o JSON)
	//		return json_decode($userinfo);
	//	} else {
	//		// Caso ocorra erro, retorna um erro com o conteúdo da resposta
	//		$error = array(
	//			'code' => 'userinfo_error',
	//			'message' => 'Failed when attempting to query for user information',
	//			'raw' => array(
	//				'response' => $userinfo,
	//				'headers' => $headers
	//			)
	//		);
	//		$this->errorCallback($error);
	//	}
	//}

	public static function checkFileType($filename)
	{
		$finfo = finfo_open(FILEINFO_MIME_TYPE);
		$mimetype = finfo_file($finfo, $filename);
		if ($mimetype == 'image/jpg' || $mimetype == 'image/jpeg' || $mimetype == 'image/gif' || $mimetype == 'image/png') {
			$is_image = true;
		} else {
			$is_image = false;
		}

		return $is_image;
	}

	public static function getFile($owner, $url, $token){

		$curl = new Curl;
		$curl->setHeader('Authorization', "Bearer {$token}");
		$curl->get($url);
		$curl->close();
		$response = $curl->response;

		if(mb_strpos($response, 'não encontrada')){
			return;
		}
		
		$tmp = tempnam("/tmp", "");
		$handle = fopen($tmp, "wb");
		fwrite($handle,$response);
		fclose($handle);

		if(!self::checkFileType($tmp)){
			return;
		}

		$class_name = $owner->fileClassName;

		$basename = md5(time()).".jpg";

		$file = new $class_name([
			"name" => $basename,
			"type" => mime_content_type($tmp),
			"tmp_name" => $tmp,
			"error" => 0,
			"size" => filesize($tmp)
		]);

		$file->group = "avatar";
		$file->owner = $owner;
		$file->save(true);
	}

	public static function newAccountCheck($response)
	{
		$app = App::i();

		$user = null;
		$cpf = self::mask($response['auth']['info']['cpf'],'###.###.###-##');
		$metadataFieldCpf = env('AUTH_METADATA_FIELD_DOCUMENT', 'documento');
		
		$agent_meta = null;
		if($am = $app->repo('AgentMeta')->findOneBy(["key" => $metadataFieldCpf, "value" => $cpf])){
			$agent_meta = $am;
		}elseif($am = $app->repo('AgentMeta')->findOneBy(["key" => $metadataFieldCpf, "value" => $response['auth']['info']['cpf']])){
			$agent_meta = $am;
		}

        if($agent_meta){
			$agent = $agent_meta->owner;
			$user = $agent->user;

			if(!$agent->isUserProfile){
				$user = new Entities\User;
				$user->authProvider = $response['auth']['provider'];
				$user->authUid = $response['auth']['uid'];
				$user->email = $response['auth']['info']['email'];
	
				$app->em->persist($user);

				$agent->userId = $user->id;
				$agent->save(true);
				$agent->refresh();
				// $app->em->flush();

				$user->profile = $agent;
				$user->save(true);

				$user->createPermissionsCacheForUsers([$user]);
            	$agent->createPermissionsCacheForUsers([$user]);
			}
		}

		return $user;

	}

	public static function applySeal($user, $response){
		$app = App::i();

		$agent = $user->profile;
		$sealId = $response['auth']['applySeal'];

		if($sealId){
			$app->disableAccessControl();

			$seal = $app->repo('Seal')->find($sealId);
			$relations = $agent->getSealRelations();

			$has_new_seal = false;
			foreach($relations as $relation){
				if($relation->seal->id == $seal->id){
					$has_new_seal = true;
					break;
				}
			}

			if(!$has_new_seal){
				$agent->createSealRelation($seal);
			}
			
			$app->enableAccessControl();

		}
	}

	public static function verifyUpdateData($user, $response)
	{
		$app = App::i();

		// if(isset($app->config['app.log.auth']) && $app->config['app.log.auth']) {
		// 	$app->log->debug("=======================================\n". __METHOD__. "::RAW::" . print_r($response['auth']['raw'], true) . "=======================================\n");
		// 	$app->log->debug("=======================================\n". __METHOD__. "::INFO::" . print_r($response['auth']['info'], true) . "=======================================\n");
		// }

		$auth_data = $response['auth']['info'];
		$userinfo = (object) $response['auth']['raw'];

		$app->hook("entity(Agent).get(lockedFields)", function(&$lockedFields) use ($app){
			$config = $app->config['auth.config']['strategies']['AcessoCidadaoES'];
			$fieladsUnlocked = array_keys($config['dic_agent_fields_update']);
			$lockedFields = array_diff($lockedFields, $fieladsUnlocked);
		});
		
		$app->disableAccessControl();
		foreach($auth_data['dic_agent_fields_update'] as $entity_key => $ref){
			if($user->profile->$entity_key != $auth_data[$ref]){
				if(($entity_key == "name") && ($user->profile->name == "" || $user->profile->name === "Meu Nome")){
					$user->profile->$entity_key = $auth_data[$ref];
				}else{
					$user->profile->$entity_key = $auth_data[$ref];
				}
			}
		}
		$user->profile->save(true);
		$app->enableAccessControl();

		if($allAgents = $app->repo("Agent")->findBy(['userId' => $user->id, '_type' => 1])){
			
			if(count($allAgents) == 1){
				$_agent = $allAgents[0];
				$_agent->setAsUserProfile();
			}
		}
		
		//self::getFile($user->profile, $userinfo->picture, $userinfo->access_token);
	}

	public static function  mask($val, $mask) {
        if (strlen($val) == strlen($mask)) return $val;
        $maskared = '';
        $k = 0;
        for($i = 0; $i<=strlen($mask)-1; $i++) {
            if($mask[$i] == '#') {
                if(isset($val[$k]))
                    $maskared .= $val[$k++];
            } else {
                if(isset($mask[$i]))
                    $maskared .= $mask[$i];
            }
        }
        return $maskared;
    }
}
