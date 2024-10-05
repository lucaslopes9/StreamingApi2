<?php
	include("conexao.php");
	include_once("functions.php");
	include_once(Idioma(1));

	if(ProtegePag() == true){
	global $_TRA;
	
	$ColunaRev = array('RevVisualizar');
	$VerificarAcesso = VerificarAcesso('rev', $ColunaRev);
	$AdminVisualizar = $VerificarAcesso[0];
 
	if($AdminVisualizar == 'S'){
	
	$CadUserOnline = InfoUser(2);
	$ArvoreAdminOnline = ArvoreAdminRev($CadUserOnline);
	$ArvoreAdminOnline[] = $CadUserOnline;
	
	if ($_SERVER['REQUEST_METHOD'] == 'POST') {

	$id = (isset($_POST['id'])) ? $_POST['id'] : '';
	
	$SQLUser = "SELECT CadUser, nome, sobrenome, usuario, senha, email, celular, perfil, data_cadastro, data_premio, VencEmail, VencSMS, ValorCobrado FROM usuario WHERE usuario = :usuario";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':usuario', $id, PDO::PARAM_STR);
	$SQLUser->execute();
	$LnUser = $SQLUser->fetch();
		
	if(empty($id)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(!in_array($LnUser['CadUser'], $ArvoreAdminOnline)) {
		echo MensagemAlerta($_TRA['erro'], str_replace("USER_TAG",$id,$_TRA['npounpav']), "danger");
	}
	else{	
	
	$nome = empty($LnUser['nome']) ? "" : $LnUser['nome'];
	$sobrenome = empty($LnUser['sobrenome']) ? "" : $LnUser['sobrenome'];
	$usuario = empty($LnUser['usuario']) ? "" : $LnUser['usuario'];
	$senha = empty($LnUser['senha']) ? "" : $LnUser['senha'];
	$email = empty($LnUser['email']) ? "" : $LnUser['email'];
	$celular = empty($LnUser['celular']) ? "" : $LnUser['celular'];
	$perfil = empty($LnUser['perfil']) ? "" : $LnUser['perfil'];
	$data_cadastro = empty($LnUser['data_cadastro']) ? "" : $LnUser['data_cadastro'];
	$data_premio = empty($LnUser['data_premio']) ? "" : $LnUser['data_premio'];
	$VencEmail = empty($LnUser['VencEmail']) ? "" : $LnUser['VencEmail'];
	$VencSMS = empty($LnUser['VencSMS']) ? "" : $LnUser['VencSMS'];
	$ValorCobrado = empty($LnUser['ValorCobrado']) ? "" : $LnUser['ValorCobrado'];
	$PrePago = "N";
	$Cota = 0;
	$CotaDias = 0;
	
	//Adiciona Revendedor
	$SQL = "INSERT INTO rev (
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
			VencSMS,
			PrePago,
			Cota,
			CotaDias,
			ValorCobrado
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
			:VencSMS,
			:PrePago,
			:Cota,
			:CotaDias,
			:ValorCobrado
			)";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUserOnline, PDO::PARAM_STR); 
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
	$SQL->bindParam(':PrePago', $PrePago, PDO::PARAM_STR);
	$SQL->bindParam(':Cota', $Cota, PDO::PARAM_STR);
	$SQL->bindParam(':CotaDias', $CotaDias, PDO::PARAM_STR);
	$SQL->bindParam(':ValorCobrado', $ValorCobrado, PDO::PARAM_STR);
	$SQL->execute(); 
	
	//Deletar Usuário
	$ExcluirPorUsuario = ExcluirPorUsuario($id);
	$SQL = "DELETE FROM usuario WHERE usuario = :usuario";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':usuario', $id, PDO::PARAM_STR); 
	$SQL->execute(); 
		
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ucarcs'], "success", "index.php?p=revendedor");
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