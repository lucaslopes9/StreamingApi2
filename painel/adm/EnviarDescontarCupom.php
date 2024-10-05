<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$AcessoUser = InfoUser(3);
if( ($AcessoUser == 3) || ($AcessoUser == 4) ){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$Cupom = (isset($_POST['Cupom'])) ? trim($_POST['Cupom']) : '';
	$CadUser = InfoUser(2);
	
	$SQL = "SELECT dias, perfil, UserDescontar FROM cupom WHERE Cupom = :Cupom";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':Cupom', $Cupom, PDO::PARAM_STR);
	$SQL->execute();
	$TotalCupom = count($SQL->fetchAll());
	
	if(empty($Cupom)){
		echo MensagemAlerta($_TRA['erro'], "Cupom é um campo obrigatório!", "danger");
	}
	if($TotalCupom == 0){
		echo MensagemAlerta($_TRA['erro'], "Cupom não existe!", "danger");
	}
	elseif(empty($CadUser)){
		echo MensagemAlerta($_TRA['erro'], "Como você fez isso?", "danger");
	}
	else{
		
	$SQL->execute();
	$Ln = $SQL->fetch();
	$Dias = trim($Ln['dias']);
	$EditarPerfil = trim($Ln['perfil']);
	$UserDescontar = trim($Ln['UserDescontar']);
		
	if(!empty($UserDescontar)){
		echo MensagemAlerta($_TRA['erro'], "Cupom inválido, já foi descontado!", "danger");		
	}
	else{
		
	$DataAtual = time();
				
	$SQLUser = "SELECT data_premio, grupo FROM usuario WHERE usuario = :usuario UNION ALL SELECT data_premio, grupo FROM teste WHERE usuario = :usuario";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':usuario', $CadUser, PDO::PARAM_STR);
	$SQLUser->execute();
	$TotalUser = count($SQLUser->fetchAll());
		
	if($TotalUser > 0){
		$SQLUser->execute();
		$LnUser = $SQLUser->fetch();
		$grupo = $LnUser['grupo'];
		$data_premio = $LnUser['data_premio'];
	
		if($data_premio < $DataAtual){
			$EditarPremium = $DataAtual + (3600 * 24 * $Dias);
		}
		else{
			$EditarPremium = $data_premio + (3600 * 24 * $Dias);
		}
		
		if($grupo == 3){
			$SQLAUser = "UPDATE usuario SET
				data_premio = :data_premio,
				perfil = :perfil
				WHERE usuario = :usuario";
			$SQLAUser = $painel_user->prepare($SQLAUser);
			$SQLAUser->bindParam(':data_premio', $EditarPremium, PDO::PARAM_STR); 
			$SQLAUser->bindParam(':perfil', $EditarPerfil, PDO::PARAM_STR);
			$SQLAUser->bindParam(':usuario', $CadUser, PDO::PARAM_STR); 
			$SQLAUser->execute();
		}
		else{
			$SQLTeste = "SELECT CadUser, nome, sobrenome, usuario, senha, email, celular, perfil, data_cadastro, data_premio, VencEmail, VencSMS FROM teste WHERE usuario = :usuario";
			$SQLTeste = $painel_user->prepare($SQLTeste);
			$SQLTeste->bindParam(':usuario', $CadUser, PDO::PARAM_STR);
			$SQLTeste->execute();
			$LnTeste = $SQLTeste->fetch();
			
			$CadUserTeste = empty($LnTeste['CadUser']) ? "" : $LnTeste['CadUser'];
			$nome = empty($LnTeste['nome']) ? "" : $LnTeste['nome'];
			$sobrenome = empty($LnTeste['sobrenome']) ? "" : $LnTeste['sobrenome'];
			$usuario = empty($LnTeste['usuario']) ? "" : $LnTeste['usuario'];
			$senha = empty($LnTeste['senha']) ? "" : $LnTeste['senha'];
			$email = empty($LnTeste['email']) ? "" : $LnTeste['email'];
			$celular = empty($LnTeste['celular']) ? "" : $LnTeste['celular'];
			$data_cadastro = empty($LnTeste['data_cadastro']) ? "" : $LnTeste['data_cadastro'];
			$VencEmail = empty($LnTeste['VencEmail']) ? "" : $LnTeste['VencEmail'];
			$VencSMS = empty($LnTeste['VencSMS']) ? "" : $LnTeste['VencSMS'];
	
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
			$SQL->bindParam(':CadUser', $CadUserTeste, PDO::PARAM_STR); 
			$SQL->bindParam(':nome', $nome, PDO::PARAM_STR); 
			$SQL->bindParam(':sobrenome', $sobrenome, PDO::PARAM_STR); 
			$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR); 
			$SQL->bindParam(':senha', $senha, PDO::PARAM_STR); 
			$SQL->bindParam(':email', $email, PDO::PARAM_STR);
			$SQL->bindParam(':celular', $celular, PDO::PARAM_STR); 
			$SQL->bindParam(':perfil', $EditarPerfil, PDO::PARAM_STR);
			$SQL->bindParam(':data_cadastro', $data_cadastro, PDO::PARAM_STR);
			$SQL->bindParam(':data_premio', $EditarPremium, PDO::PARAM_STR);
			$SQL->bindParam(':VencEmail', $VencEmail, PDO::PARAM_STR);
			$SQL->bindParam(':VencSMS', $VencSMS, PDO::PARAM_STR);
			$SQL->execute(); 
	
			//Deletar Usuário
			$SQL = "DELETE FROM teste WHERE usuario = :usuario";
			$SQL = $painel_user->prepare($SQL);
			$SQL->bindParam(':usuario', $CadUser, PDO::PARAM_STR); 
			$SQL->execute(); 
		}
		
			$SQLCup = "UPDATE cupom SET
				UserDescontar = :UserDescontar,
				UserDescontarEm = :UserDescontarEm
				WHERE Cupom = :Cupom";
			$SQLCup = $painel_geral->prepare($SQLCup);
			$SQLCup->bindParam(':UserDescontar', $CadUser, PDO::PARAM_STR); 
			$SQLCup->bindParam(':UserDescontarEm', $DataAtual, PDO::PARAM_STR);
			$SQLCup->bindParam(':Cupom', $Cupom, PDO::PARAM_STR); 
			$SQLCup->execute();
		
		$_SESSION['acesso'] = 3;
		$_SESSION['data_premio'] = $EditarPremium;
	}
		
	
	if(empty($SQLCup)){
		echo MensagemAlerta($_TRA['erro'], "Erro ao descontar o cupom!", "danger", "index.php?p=cupom");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], "Cupom descontado com sucesso!", "success", "index.php?p=cupom");
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