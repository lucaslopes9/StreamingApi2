<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('OpcoesExportar');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesExportar = $VerificarAcesso[0];

if($OpcoesExportar == 'S'){

$usuario = empty($_POST['usuario']) ? '' : $_POST['usuario'];

if(empty($usuario)){
	echo MensagemAlerta($_TRA['erro'], $_TRA['UCO'], "danger");
}
else{
	echo "<xml-user-manager ver=\"1.0\">\n";
	
	$return = "";
	
	if($usuario == "Todos"){
	
	$usuario = InfoUser(2);
	$CadUser = ArvoreAdminRev($usuario);
	$CadUser[] = $usuario;
	$CadUser = implode(',', $CadUser);
	
	//Revendedor
	$SQLRev = "SELECT CadUser, usuario, senha, nome, email, perfil, data_cadastro, data_premio, celular, PrePago, Cota, CotaDias FROM rev WHERE FIND_IN_SET(CadUser,:CadUser)";
	$SQLRev = $painel_user->prepare($SQLRev);
	$SQLRev->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQLRev->execute();
	
	//Usuario
	$SQLUser = "SELECT CadUser, usuario, senha, nome, email, perfil, conexao, data_cadastro, data_premio, celular FROM usuario WHERE FIND_IN_SET(CadUser,:CadUser)";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQLUser->execute();
	
	//Teste
	$SQLTeste = "SELECT CadUser, usuario, senha, nome, email, perfil, conexao, data_cadastro, data_premio, celular FROM teste WHERE FIND_IN_SET(CadUser,:CadUser)";
	$SQLTeste = $painel_user->prepare($SQLTeste);
	$SQLTeste->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
	$SQLTeste->execute();
		
	}
	else{
	
	//Revendedor	
	$SQLRev = "SELECT CadUser, usuario, senha, nome, email, perfil, data_cadastro, data_premio, celular, PrePago, Cota, CotaDias FROM rev WHERE CadUser = :CadUser";
	$SQLRev = $painel_user->prepare($SQLRev);
	$SQLRev->bindParam(':CadUser', $usuario, PDO::PARAM_STR); 
	$SQLRev->execute();
	
	//Usuario
	$SQLUser = "SELECT CadUser, usuario, senha, nome, email, perfil, conexao, data_cadastro, data_premio, celular FROM usuario WHERE CadUser = :CadUser";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':CadUser', $usuario, PDO::PARAM_STR); 
	$SQLUser->execute();
	
	//Teste
	$SQLTeste = "SELECT CadUser, usuario, senha, nome, email, perfil, conexao, data_cadastro, data_premio, celular FROM teste WHERE CadUser = :CadUser";
	$SQLTeste = $painel_user->prepare($SQLTeste);
	$SQLTeste->bindParam(':CadUser', $usuario, PDO::PARAM_STR); 
	$SQLTeste->execute();
	
	}
	
	//Revendedor
	while($LnSelectRev = $SQLRev->fetch()){
	
		$profile = str_replace("[","",$LnSelectRev['perfil']);
		$profile = str_replace("]"," ",$profile);
		$profile = trim($profile);
	
		$data_cadastro = date('Y-m-d', strtotime($LnSelectRev['data_cadastro']));
		$data_premio = date('Y-m-d', $LnSelectRev['data_premio']);
		
		$return .= "<user name=\"".$LnSelectRev['usuario']."\" password=\"".$LnSelectRev['senha']."\" display-name=\"".$LnSelectRev['nome']."\" email-address=\"".$LnSelectRev['email']."\" caduser=\"".$LnSelectRev['CadUser']."\" celular=\"".$LnSelectRev['celular']."\" profiles=\"".$profile."\" start-date=\"".$data_cadastro."\" expire-date=\"".$data_premio."\" PrePago=\"".$LnSelectRev['PrePago']."\" Cota=\"".$LnSelectRev['Cota']."\" CotaDias=\"".$LnSelectRev['CotaDias']."\" tipo=\"1\"/>\n";
	}
	
	//Usuario
	while($LnSelectUser = $SQLUser->fetch()){
	
		$profile = str_replace("[","",$LnSelectUser['perfil']);
		$profile = str_replace("]"," ",$profile);
		$profile = trim($profile);
	
		$data_cadastro = date('Y-m-d', strtotime($LnSelectUser['data_cadastro']));
		$data_premio = date('Y-m-d', $LnSelectUser['data_premio']);
		
		$return .= "<user name=\"".$LnSelectUser['usuario']."\" password=\"".$LnSelectUser['senha']."\" display-name=\"".$LnSelectUser['nome']."\" email-address=\"".$LnSelectUser['email']."\" caduser=\"".$LnSelectUser['CadUser']."\" celular=\"".$LnSelectUser['celular']."\" profiles=\"".$profile."\" max-connections=\"".$LnSelectUser['conexao']."\" start-date=\"".$data_cadastro."\" expire-date=\"".$data_premio."\" tipo=\"2\"/>\n";
	}
	
	//Teste
	while($LnSelectTeste = $SQLTeste->fetch()){
	
		$profile = str_replace("[","",$LnSelectTeste['perfil']);
		$profile = str_replace("]"," ",$profile);
		$profile = trim($profile);
	
		$data_cadastro = date('Y-m-d', strtotime($LnSelectTeste['data_cadastro']));
		$data_premio = date('Y-m-d', $LnSelectTeste['data_premio']);
		
		$return .= "<user name=\"".$LnSelectTeste['usuario']."\" password=\"".$LnSelectTeste['senha']."\" display-name=\"".$LnSelectTeste['nome']."\" email-address=\"".$LnSelectTeste['email']."\" caduser=\"".$LnSelectTeste['CadUser']."\" celular=\"".$LnSelectTeste['celular']."\" profiles=\"".$profile."\" max-connections=\"".$LnSelectTeste['conexao']."\" start-date=\"".$data_cadastro."\" expire-date=\"".$data_premio."\" tipo=\"3\"/>\n";
	}
		
	echo $return;
	echo "</xml-user-manager>";
	
	
}

}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}
?>