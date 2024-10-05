<?php
	include("conexao.php");
	include_once("functions.php");
	include_once(Idioma(1));

	if(ProtegePag() == true){
	global $_TRA;
	
	$ColunaAdmin = array('AdminExcluir');
	$VerificarAcesso = VerificarAcesso('admin', $ColunaAdmin);
	$AdminExcluir = $VerificarAcesso[0];
 
	if($AdminExcluir == 'S'){
	
	$CadUserOnline = InfoUser(2);
	$ArvoreAdminOnline = ArvoreAdmin($CadUserOnline);
	
	if ($_SERVER['REQUEST_METHOD'] == 'POST') {

	$id = (isset($_POST['id'])) ? $_POST['id'] : '';
		
	if(empty($id)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['cvfi'], "danger");
	}
	elseif(!in_array($id, $ArvoreAdminOnline)) {
		echo MensagemAlerta($_TRA['erro'], str_replace("USER_TAG",$id,$_TRA['npounpav']), "danger");
	}
	else{	
	
	//Administrador 
	$ArvoreAdmin = ArvoreAdmin($id);
	if(!empty($ArvoreAdmin)){
		for($i = 0; $i < count($ArvoreAdmin); $i++){
		$ExcluirPorUsuario = ExcluirPorUsuario($ArvoreAdmin[$i]);
		}
	}
	
	//Revendedor 
	$ArvoreRev = ArvoreRev($id);
	if(!empty($ArvoreRev)){
		for($i = 0; $i < count($ArvoreRev); $i++){
		$ExcluirPorUsuario = ExcluirPorUsuario($ArvoreRev[$i]);
		}
	}
	
	//Usuário 
	$ArvoreUser = ArvoreUser($id);
	if(!empty($ArvoreUser)){
		for($i = 0; $i < count($ArvoreUser); $i++){
		$ExcluirPorUsuario = ExcluirPorUsuario($ArvoreUser[$i]);
		}
	}
	
	//Teste 
	$ArvoreTeste = ArvoreTeste($id);
	if(!empty($ArvoreTeste)){
		for($i = 0; $i < count($ArvoreTeste); $i++){
		$ExcluirPorUsuario = ExcluirPorUsuario($ArvoreTeste[$i]);
		}
	}
	
	//Deletar Usuário
	$ExcluirPorUsuario = ExcluirPorUsuario($id);
	$SQL = "DELETE FROM admin WHERE usuario = :usuario";
	$SQL = $painel_user->prepare($SQL);
	$SQL->bindParam(':usuario', $id, PDO::PARAM_STR); 
	$SQL->execute(); 
		
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['ecs'], "success", "index.php?p=administrador");
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