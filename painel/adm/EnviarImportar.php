<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('OpcoesImportar');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesExportar = $VerificarAcesso[0];

if($OpcoesExportar == 'S'){

$usuario = empty($_POST['usuario']) ? '' : $_POST['usuario'];
$mensagem = empty($_POST['mensagem']) ? '' : $_POST['mensagem'];
$acesso = InfoUser(3);

if(empty($usuario)){
	echo MensagemAlerta($_TRA['erro'], $_TRA['UCO'], "danger");
}
elseif(empty($mensagem)){
	echo MensagemAlerta($_TRA['erro'], $_TRA['meuco'], "danger");
}
else{
	
	$e = explode("<user", $mensagem);
	for($i = 1; $i < count($e); $i++){
	$ResultFinal = $e[$i];
	
	$Revendedor = cut_str($ResultFinal, 'caduser="', '"');
	$name = cut_str($ResultFinal, 'name="', '"');
	$password = cut_str($ResultFinal, 'password="', '"');
	$displayname = cut_str($ResultFinal, 'display-name="', '"');
	$emailaddress = cut_str($ResultFinal, 'email-address="', '"');
	$profiles = cut_str($ResultFinal, 'profiles="', '"');
	$maxconnections = cut_str($ResultFinal, 'max-connections="', '"');
	$startdate = trim(cut_str($ResultFinal, 'start-date="', '"'));
	$expiredate = trim(cut_str($ResultFinal, 'expire-date="', '"'));
	$celular = cut_str($ResultFinal, 'celular="', '"');
	$tipo = cut_str($ResultFinal, 'tipo="', '"');	
	$PrePago = cut_str($ResultFinal, 'PrePago="', '"');
	$Cota = cut_str($ResultFinal, 'Cota="', '"');
	$CotaDias = cut_str($ResultFinal, 'CotaDias="', '"');
	
	$FormStart = FormatoData($startdate);
	$FormExpire = FormatoData($expiredate);
		
		if(empty($name)){
			echo $name.": ".$_TRA['UCO'];
			echo "\n";
		}
		elseif(substr_count($name, " ") > 0){
			echo $name.": ".$_TRA['unpce'];
			echo "\n";
		}
		if(VerificarUsuarioEditar($name, NULL, $acesso) == 1) {
			echo $name.": ".$_TRA['uieeu'];
			echo "\n";
		}
		elseif( !empty($emailaddress) && substr_count($emailaddress, "@") == 0 || !empty($emailaddress) && substr_count($emailaddress, ".") == 0) {
			echo $name.": ".$_TRA['dei'];
			echo "\n";
		}
		elseif( !empty($tipo) && ($tipo != 1) && ($tipo != 2) && ($tipo != 3) ){
			echo $name.": ".$_TRA['TipoInvalido'];
			echo "\n";
		}
		else{
						
		$startdate = $FormStart;
		$expiredate = strtotime($FormExpire);
		$profiles = ConverterPerfil($profiles);
			
		
			if($usuario == "Todos"){
			
			//Revendedor
			if($tipo == 1){
			$SQL = "INSERT INTO rev (
				CadUser,
				nome,
           		usuario,
				senha,
				email,
				perfil,
				data_cadastro,
				data_premio,
				celular,
				PrePago,
				Cota,
				CotaDias
           	) VALUES (
				:CadUser,
				:nome,
           		:usuario,
				:senha,
				:email,
				:perfil,
				:data_cadastro,
				:data_premio,
				:celular,
				:PrePago,
				:Cota,
				:CotaDias
			)";
			$SQL = $painel_user->prepare($SQL);
			$SQL->bindParam(':CadUser', $Revendedor, PDO::PARAM_STR); 
			$SQL->bindParam(':nome', $displayname, PDO::PARAM_STR); 
			$SQL->bindParam(':usuario', $name, PDO::PARAM_STR); 
			$SQL->bindParam(':senha', $password, PDO::PARAM_STR); 
			$SQL->bindParam(':email', $emailaddress, PDO::PARAM_STR);
			$SQL->bindParam(':perfil', $profiles, PDO::PARAM_STR);
			$SQL->bindParam(':data_cadastro', $startdate, PDO::PARAM_STR);
			$SQL->bindParam(':data_premio', $expiredate, PDO::PARAM_STR);
			$SQL->bindParam(':celular', $celular, PDO::PARAM_STR);
			$SQL->bindParam(':PrePago', $PrePago, PDO::PARAM_STR);
			$SQL->bindParam(':Cota', $Cota, PDO::PARAM_STR);
			$SQL->bindParam(':CotaDias', $Cota, PDO::PARAM_STR);
			$SQL->execute(); 
			
			}
			
			//Usuário
			elseif($tipo == 2){
			$SQL = "INSERT INTO usuario (
				CadUser,
				nome,
           		usuario,
				senha,
				email,
				conexao,
				perfil,
				data_cadastro,
				data_premio,
				celular
           	) VALUES (
				:CadUser,
				:nome,
           		:usuario,
				:senha,
				:email,
				:conexao,
				:perfil,
				:data_cadastro,
				:data_premio,
				:celular
			)";
			$SQL = $painel_user->prepare($SQL);
			$SQL->bindParam(':CadUser', $Revendedor, PDO::PARAM_STR); 
			$SQL->bindParam(':nome', $displayname, PDO::PARAM_STR); 
			$SQL->bindParam(':usuario', $name, PDO::PARAM_STR); 
			$SQL->bindParam(':senha', $password, PDO::PARAM_STR); 
			$SQL->bindParam(':email', $emailaddress, PDO::PARAM_STR);
			$SQL->bindParam(':conexao', $maxconnections, PDO::PARAM_STR);
			$SQL->bindParam(':conexao', $maxconnections, PDO::PARAM_STR);
			$SQL->bindParam(':perfil', $profiles, PDO::PARAM_STR);
			$SQL->bindParam(':data_cadastro', $startdate, PDO::PARAM_STR);
			$SQL->bindParam(':data_premio', $expiredate, PDO::PARAM_STR);
			$SQL->bindParam(':celular', $celular, PDO::PARAM_STR);
			$SQL->execute(); 
			}
			
			//Teste
			elseif($tipo == 3){
			$SQL = "INSERT INTO teste (
				CadUser,
				nome,
           		usuario,
				senha,
				email,
				conexao,
				perfil,
				data_cadastro,
				data_premio,
				celular
           	) VALUES (
				:CadUser,
				:nome,
           		:usuario,
				:senha,
				:email,
				:conexao,
				:perfil,
				:data_cadastro,
				:data_premio,
				:celular
			)";
			$SQL = $painel_user->prepare($SQL);
			$SQL->bindParam(':CadUser', $Revendedor, PDO::PARAM_STR); 
			$SQL->bindParam(':nome', $displayname, PDO::PARAM_STR); 
			$SQL->bindParam(':usuario', $name, PDO::PARAM_STR); 
			$SQL->bindParam(':senha', $password, PDO::PARAM_STR); 
			$SQL->bindParam(':email', $emailaddress, PDO::PARAM_STR);
			$SQL->bindParam(':conexao', $maxconnections, PDO::PARAM_STR);
			$SQL->bindParam(':conexao', $maxconnections, PDO::PARAM_STR);
			$SQL->bindParam(':perfil', $profiles, PDO::PARAM_STR);
			$SQL->bindParam(':data_cadastro', $startdate, PDO::PARAM_STR);
			$SQL->bindParam(':data_premio', $expiredate, PDO::PARAM_STR);
			$SQL->bindParam(':celular', $celular, PDO::PARAM_STR);
			$SQL->execute(); 
			}
			
			}
			else{
			$SQL = "INSERT INTO usuario (
				CadUser,
				nome,
           		usuario,
				senha,
				email,
				conexao,
				perfil,
				data_cadastro,
				data_premio,
				celular
           	) VALUES (
				:CadUser,
				:nome,
           		:usuario,
				:senha,
				:email,
				:conexao,
				:perfil,
				:data_cadastro,
				:data_premio,
				:celular
			)";
		$SQL = $painel_user->prepare($SQL);
		$SQL->bindParam(':CadUser', $usuario, PDO::PARAM_STR); 
		$SQL->bindParam(':nome', $displayname, PDO::PARAM_STR); 
		$SQL->bindParam(':usuario', $name, PDO::PARAM_STR); 
		$SQL->bindParam(':senha', $password, PDO::PARAM_STR); 
		$SQL->bindParam(':email', $emailaddress, PDO::PARAM_STR);
		$SQL->bindParam(':conexao', $maxconnections, PDO::PARAM_STR);
		$SQL->bindParam(':perfil', $profiles, PDO::PARAM_STR);
		$SQL->bindParam(':data_cadastro', $startdate, PDO::PARAM_STR);
		$SQL->bindParam(':data_premio', $expiredate, PDO::PARAM_STR);
		$SQL->bindParam(':celular', $celular, PDO::PARAM_STR);
		$SQL->execute(); 
		}
	
	echo $name.": ".$_TRA['uics'];
	echo "\n";
	
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