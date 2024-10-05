<?php
	include("conexao.php");
	include_once("functions.php");
	include_once(Idioma(1));

	if(ProtegePag() == true){
	global $_TRA;
	
	$ColunaAdmin = array('TesteBloquear', 'TesteExcluir');
	$VerificarAcesso = VerificarAcesso('teste', $ColunaAdmin);

	$AdminBloquear = $VerificarAcesso[0];
	$AdminExcluir = $VerificarAcesso[1];
 
	if( ($AdminBloquear == 'S') || ($AdminExcluir == 'S') ){

	$CadUserOnline = InfoUser(2);
	$ArvoreAdminOnline = ArvoreAdminRev($CadUserOnline);
	$ArvoreAdminOnline[] = $CadUserOnline;
	
	if ($_SERVER['REQUEST_METHOD'] == 'POST') {

	$camposMarcados = (isset($_POST['camposMarcados'])) ? $_POST['camposMarcados'] : '';
	$status = (isset($_POST['status'])) ? $_POST['status'] : '';
	$rev = (isset($_POST['rev'])) ? $_POST['rev'] : '';
	$EditarPerfil = (isset($_POST['EditarPerfil'])) ? $_POST['EditarPerfil'] : '';
	$assunto = (isset($_POST['assunto'])) ? $_POST['assunto'] : '';
	$mensagem = (isset($_POST['mensagem'])) ? $_POST['mensagem'] : '';
	$EnviarCOM = (isset($_POST['EnviarCOM'])) ? $_POST['EnviarCOM'] : '';
		
	$VerificarVerEmail = VerificarVerEmail($CadUserOnline);
	
	if( empty($EditarPerfil) && ($status == "perfil") ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['sepmup'], "danger");
	}
	elseif( empty($EnviarCOM) && ($status == "email") ){
		echo MensagemAlerta($_TRA['erro'], "Selecione um e-mail para o envio!", "danger");
	}
	elseif( empty($assunto) && ($status == "email") ){
		echo MensagemAlerta($_TRA['erro'], "Assunto é um campo obrigatório!", "danger");
	}	
	elseif(empty($mensagem) && ($status == "email") ){
		echo MensagemAlerta($_TRA['erro'], "Mensagem é um campo obrigatório!", "danger");
	}
	elseif( ($mensagem == "<p><br></p>") && ($status == "email") ){
		echo MensagemAlerta($_TRA['erro'], "Mensagem é um campo obrigatório!", "danger");
	}
	elseif(empty($camposMarcados)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['spmuu'], "danger");
	}
	elseif(empty($status)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['spmuo'], "danger");
	}
	elseif( ($VerificarVerEmail == 1) && ($status == "email") ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['cueeeacq'], "danger");
	}
	elseif( ($VerificarVerEmail == 2) && ($status == "email") ) {
		echo MensagemAlerta($_TRA['erro'], $_TRA['oeaesb'], "danger");
	}
	else{	
		
		if( $status == "perfil" ){
			$profile = trim(implode("", $EditarPerfil));
			$EditarPerfil = empty($profile) ? "" : $profile;
		}
		elseif( $status == "email" ){
			$ArrayEmail = array();
		}
	
		for($i = 0; $i < count($camposMarcados); $i++){
			
			$SQLUser = "SELECT CadUser FROM teste WHERE usuario = :usuario";
			$SQLUser = $painel_user->prepare($SQLUser);
			$SQLUser->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR);
			$SQLUser->execute();
			$LnUser = $SQLUser->fetch();
	
			if(!in_array($LnUser['CadUser'], $ArvoreAdminOnline)) {
				echo MensagemAlerta($_TRA['erro'], str_replace("USER_TAG",$camposMarcados[$i],$_TRA['npounpav']), "danger");
				exit;
			}
			else{
				
				if( $status == "tornaruser" ){
					
					$SQLUser = "SELECT CadUser, nome, sobrenome, usuario, senha, email, celular, perfil, data_cadastro, data_premio, VencEmail, VencSMS FROM teste WHERE usuario = :usuario";
					$SQLUser = $painel_user->prepare($SQLUser);
					$SQLUser->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR);
					$SQLUser->execute();
					$LnUser = $SQLUser->fetch();
					
					$CadUser = empty($LnUser['CadUser']) ? "" : $LnUser['CadUser'];
					$nome = empty($LnUser['nome']) ? "" : $LnUser['nome'];
					$sobrenome = empty($LnUser['sobrenome']) ? "" : $LnUser['sobrenome'];
					$usuario = empty($LnUser['usuario']) ? "" : $LnUser['usuario'];
					$senha = empty($LnUser['senha']) ? "" : $LnUser['senha'];
					$email = empty($LnUser['email']) ? "" : $LnUser['email'];
					$celular = empty($LnUser['celular']) ? "" : $LnUser['celular'];
					$perfil = empty($LnUser['perfil']) ? "" : $LnUser['perfil'];
					$data_cadastro = empty($LnUser['data_cadastro']) ? "" : $LnUser['data_cadastro'];
					$VencEmail = empty($LnUser['VencEmail']) ? "" : $LnUser['VencEmail'];
					$VencSMS = empty($LnUser['VencSMS']) ? "" : $LnUser['VencSMS'];
					
					$DataAtual = time();
					$data_premio = $DataAtual + 3600 * 24 * 30;
					
					//Adiciona Usuário
					$SQL = "INSERT INTO usuario (
							CadUser,
							nome,
            				sobrenome,
							usuario,
							senha,
							email,
							celular,
							perfil,
							data_cadastro,
							data_premio,
							VencEmail,
							VencSMS
							) VALUES (
							:CadUser,
							:nome,
            				:sobrenome,
            				:usuario,
							:senha,
							:email,
							:celular,
							:perfil,
							:data_cadastro,
							:data_premio,
							:VencEmail,
							:VencSMS
							)";
					$SQL = $painel_user->prepare($SQL);
					$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
					$SQL->bindParam(':nome', $nome, PDO::PARAM_STR); 
					$SQL->bindParam(':sobrenome', $sobrenome, PDO::PARAM_STR); 
					$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR); 
					$SQL->bindParam(':senha', $senha, PDO::PARAM_STR); 
					$SQL->bindParam(':email', $email, PDO::PARAM_STR);
					$SQL->bindParam(':celular', $celular, PDO::PARAM_STR); 
					$SQL->bindParam(':perfil', $perfil, PDO::PARAM_STR);
					$SQL->bindParam(':data_cadastro', $data_cadastro, PDO::PARAM_STR);
					$SQL->bindParam(':data_premio', $data_premio, PDO::PARAM_STR);
					$SQL->bindParam(':VencEmail', $VencEmail, PDO::PARAM_STR);
					$SQL->bindParam(':VencSMS', $VencSMS, PDO::PARAM_STR);
					$SQL->execute(); 
					
					//Deletar Usuário
					$ExcluirPorUsuario = ExcluirPorUsuario($camposMarcados[$i]);
					$SQL = "DELETE FROM teste WHERE usuario = :usuario";
					$SQL = $painel_user->prepare($SQL);
					$SQL->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR); 
					$SQL->execute(); 
					
				}
				elseif( $status == "email" ){
					if($rev != $camposMarcados[$i]){
						$SQLVer = "SELECT email FROM teste WHERE usuario = :usuario";
						$SQLVer = $painel_user->prepare($SQLVer);
						$SQLVer->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR);
						$SQLVer->execute();
						$LnVer = $SQLVer->fetch();
						$email = $LnVer['email'];
						
						if(!empty($email)){
							if(!in_array($email, $ArrayEmail)) {
								$ArrayEmail[] = $email;
							}
						}
					}
				}
				elseif( $status == "perfil" ){
						$SQL = "UPDATE teste SET
								perfil = :perfil
            					WHERE usuario = :usuario";
						$SQL = $painel_user->prepare($SQL);
						$SQL->bindParam(':perfil', $EditarPerfil, PDO::PARAM_STR);
						$SQL->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR);
						$SQL->execute();
				}
				elseif( $status == "arvore" ){
						if($rev != $camposMarcados[$i]){
						$SQL = "UPDATE teste SET
								CadUser = :CadUser
            					WHERE usuario = :usuario";
						$SQL = $painel_user->prepare($SQL);
						$SQL->bindParam(':CadUser', $rev, PDO::PARAM_STR);
						$SQL->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR);
						$SQL->execute();
						}
				}
				elseif( ($status == "bloquear") && ($AdminBloquear == 'S')){
					$bloqueado = "S";
					$SQL = "UPDATE teste SET
					bloqueado = :bloqueado
           			WHERE usuario = :usuario";
					$SQL = $painel_user->prepare($SQL);
					$SQL->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
					$SQL->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR); 
					$SQL->execute(); 
				}
				elseif( ($status == "desbloquear") && ($AdminBloquear == 'S')){
					$bloqueado = "N";
					$SQL = "UPDATE teste SET
					bloqueado = :bloqueado
            		WHERE usuario = :usuario";
					$SQL = $painel_user->prepare($SQL);
					$SQL->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
					$SQL->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR); 
					$SQL->execute();	
				}
				elseif( ($status == "excluir") && ($AdminExcluir == 'S') ){
					//Deletar Usuário
					$ExcluirPorUsuario = ExcluirPorUsuario($camposMarcados[$i]);
					$SQL = "DELETE FROM teste WHERE usuario = :usuario";
					$SQL = $painel_user->prepare($SQL);
					$SQL->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR); 
					$SQL->execute(); 
				}
			}
		}
	
	if( $status == "email" ){
		
		if(!empty($ArrayEmail)){
			$SQLUserEmail = "SELECT servidor, exibicao, email, usuario, senha, SMTPSecure, Host, Port FROM email_adicionar WHERE CadUser = :CadUser AND id = :id";
			$SQLUserEmail = $painel_geral->prepare($SQLUserEmail);
			$SQLUserEmail->bindParam(':CadUser', $CadUserOnline, PDO::PARAM_STR);
			$SQLUserEmail->bindParam(':id', $EnviarCOM, PDO::PARAM_STR);
			$SQLUserEmail->execute();
			$LnUserEmail = $SQLUserEmail->fetch();
			
			$mensagem = ModeloCircularExibir($mensagem);
			$EnviarEmail = EnviarEmailCircular($LnUserEmail['SMTPSecure'], $LnUserEmail['Host'], $LnUserEmail['Port'], $LnUserEmail['usuario'], $LnUserEmail['senha'], $LnUserEmail['email'], $LnUserEmail['exibicao'], $ArrayEmail, $assunto, $mensagem);
		}
		
		if($EnviarEmail == 0){
			echo MensagemAlerta($_TRA['erro'], "Ocorreu um problema ao enviar e-mails", "danger", "index.php?p=teste");
		}
		else{
			echo MensagemAlerta($_TRA['sucesso'], "E-mail enviado com sucesso", "success", "index.php?p=teste");
		}
	}
	else{
		if(empty($SQL)){
			echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", "index.php?p=teste");
		}
		else{
			echo MensagemAlerta($_TRA['sucesso'], $_TRA['arcs'], "success", "index.php?p=teste");
		}
	}
	
	}
	}
	
	}else{
		echo Redirecionar('index.php');
	}
	}else{
		echo Redirecionar('login.php');
	}	

?>