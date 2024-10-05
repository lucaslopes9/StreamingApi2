<?php
	include("conexao.php");
	include_once("functions.php");
	include_once(Idioma(1));

	if(ProtegePag() == true){
	global $_TRA;
	
	$ColunaAdmin = array('UserBloquear', 'UserExcluir');
	$VerificarAcesso = VerificarAcesso('user', $ColunaAdmin);

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
	$EditarPremium = (isset($_POST['EditarPremium'])) ? $_POST['EditarPremium'] : '';
	$EditarPerfil = (isset($_POST['EditarPerfil'])) ? $_POST['EditarPerfil'] : '';
	$EditarValorCobrado = (isset($_POST['EditarValorCobrado'])) ? ConverterDinheiro($_POST['EditarValorCobrado']) : '';
	$EditarValorCobradoCab = (isset($_POST['EditarValorCobradoCab'])) ? ConverterDinheiro($_POST['EditarValorCobradoCab']) : '';
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
	elseif( empty($EditarPremium) && ($status == "vencimento") ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['dpeuco'], "danger");
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
		
		if( $status == "vencimento" ){
			$EditarPremium = ConverterData($EditarPremium, 2);
			$EditarPremium = strtotime($EditarPremium);
		}
		elseif( $status == "perfil" ){
			$profile = trim(implode("", $EditarPerfil));
			$EditarPerfil = empty($profile) ? "" : $profile;
		}
		elseif( $status == "email" ){
			$ArrayEmail = array();
		}
		
		for($i = 0; $i < count($camposMarcados); $i++){
			
			$SQLUser = "SELECT CadUser FROM usuario WHERE usuario = :usuario";
			$SQLUser = $painel_user->prepare($SQLUser);
			$SQLUser->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR);
			$SQLUser->execute();
			$LnUser = $SQLUser->fetch();
	
			if(!in_array($LnUser['CadUser'], $ArvoreAdminOnline)) {
				echo MensagemAlerta($_TRA['erro'], str_replace("USER_TAG",$camposMarcados[$i],$_TRA['npounpav']), "danger");
				exit;
			}
			else{
				
				if( $status == "email" ){
					if($rev != $camposMarcados[$i]){
						$SQLVer = "SELECT email FROM usuario WHERE usuario = :usuario";
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
				elseif( $status == "valores" ){
						$SQL = "UPDATE usuario SET
								ValorCobrado = :ValorCobrado,
								ValorCobradoCab = :ValorCobradoCab
            					WHERE usuario = :usuario";
						$SQL = $painel_user->prepare($SQL);
						$SQL->bindParam(':ValorCobrado', $EditarValorCobrado, PDO::PARAM_STR);
						$SQL->bindParam(':ValorCobradoCab', $EditarValorCobradoCab, PDO::PARAM_STR);
						$SQL->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR);
						$SQL->execute();
				}
				elseif( $status == "perfil" ){
						$SQL = "UPDATE usuario SET
								perfil = :perfil
            					WHERE usuario = :usuario";
						$SQL = $painel_user->prepare($SQL);
						$SQL->bindParam(':perfil', $EditarPerfil, PDO::PARAM_STR);
						$SQL->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR);
						$SQL->execute();
				}
				elseif( $status == "arvore" ){
						if($rev != $camposMarcados[$i]){
						$SQL = "UPDATE usuario SET
								CadUser = :CadUser
            					WHERE usuario = :usuario";
						$SQL = $painel_user->prepare($SQL);
						$SQL->bindParam(':CadUser', $rev, PDO::PARAM_STR);
						$SQL->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR);
						$SQL->execute();
						}
				}
				elseif( $status == "vencimento" ){
						$SQL = "UPDATE usuario SET
								data_premio = :data_premio
            					WHERE usuario = :usuario";
						$SQL = $painel_user->prepare($SQL);
						$SQL->bindParam(':data_premio', $EditarPremium, PDO::PARAM_STR);
						$SQL->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR);
						$SQL->execute();
				}
				elseif( ($status == "bloquear") && ($AdminBloquear == 'S')){
					$bloqueado = "S";
					$SQL = "UPDATE usuario SET
					bloqueado = :bloqueado
           			WHERE usuario = :usuario";
					$SQL = $painel_user->prepare($SQL);
					$SQL->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR); 
					$SQL->bindParam(':usuario', $camposMarcados[$i], PDO::PARAM_STR); 
					$SQL->execute(); 
				}
				elseif( ($status == "desbloquear") && ($AdminBloquear == 'S')){
					$bloqueado = "N";
					$SQL = "UPDATE usuario SET
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
					$SQL = "DELETE FROM usuario WHERE usuario = :usuario";
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
			echo MensagemAlerta($_TRA['erro'], "Ocorreu um problema ao enviar e-mails", "danger", "index.php?p=usuario");
		}
		else{
			echo MensagemAlerta($_TRA['sucesso'], "E-mail enviado com sucesso", "success", "index.php?p=usuario");
		}
	}
	else{
		if(empty($SQL)){
			echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger", "index.php?p=usuario");
		}
		else{
			echo MensagemAlerta($_TRA['sucesso'], $_TRA['arcs'], "success", "index.php?p=usuario");
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