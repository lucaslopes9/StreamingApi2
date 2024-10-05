<?php
	set_time_limit(0);
	set_include_path('ssh');
	include('ssh/Net/SSH2.php');
	include("conexao.php");
	include_once("functions.php");
	include_once(Idioma(1));
	if(ProtegePag() == true){
	global $_TRA;

	$ColunaAcesso = array('OpcoesBackup');
	$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
	$OpcoesBackup = $VerificarAcesso[0];

if($OpcoesBackup == 'S'){

	$id = (isset($_POST['id'])) ? $_POST['id'] : '';
	
	if(empty($id)){
		echo MensagemAlerta($_TRA['erro'], "Ocorreu um erro ao restaurar o banco de dados!", "danger");
		exit;
	}
	else{
		
	//Limpa os pacotes
	$SQLTruncate = "TRUNCATE arquivo_backup";
	$SQLTruncate = $painel_geral->prepare($SQLTruncate);
	$SQLTruncate->execute();
		
	$SqlStatusServer = "SELECT * FROM backup_automatizado";
	$SqlStatusServer = $painel_geral->prepare($SqlStatusServer);
	$SqlStatusServer->execute();
	$LnStatusServer = $SqlStatusServer->fetch();
	$server = $LnStatusServer['server'];
		
	$SQLServer = "SELECT * FROM server WHERE id = :id";
	$SQLServer = $painel_geral->prepare($SQLServer);
	$SQLServer->bindParam(':id', $server, PDO::PARAM_STR);
	$SQLServer->execute();
	$LnServer = $SQLServer->fetch();
	$ip = my_decrypt($LnServer['ip']);
	$porta = my_decrypt($LnServer['porta']);
	$user = my_decrypt($LnServer['user']);
	$senha = my_decrypt($LnServer['senha']);
	
	$ssh = new Net_SSH2($ip, $porta);
	if (!$ssh->login($user, $senha)) {
   		echo MensagemAlerta("Erro", "Dados do Servidor de Backup inválido, não foi possível estabelecer a conexão!", "danger");
		exit;
	}
				
	$Ln_ssh = $ssh->exec("ls /home/cs/");
		
	$explode = explode("\n",$Ln_ssh);
	for($i = 0; $i < count($explode); $i++){
		
		$TamanhoArquivo = $ssh->exec("du -hsb /home/cs/".$explode[$i]."");
		$TamanhoArquivo = intval($TamanhoArquivo);
		
		$ext = strtolower(end(explode(".", $explode[$i])));
		if($ext == "sql"){
			
			if(substr_count($explode[$i], "acessos_") > 0){
				$TipoArquivo = "Acessos";
			}
			elseif(substr_count($explode[$i], "geral_") > 0){
				$TipoArquivo = "Geral";
			}
			elseif(substr_count($explode[$i], "user_") > 0){
				$TipoArquivo = "Usuário";
			}
			
			$DataArquivo = strtolower(end(explode("_", $explode[$i])));
			$DataArquivo = trim(str_replace(".".$ext."","",$DataArquivo));
			
			
			$SQL = "INSERT INTO arquivo_backup (
				tipo,
				local,
				data,
				size
            ) VALUES (
				:tipo,
				:local,
				:data,
				:size
			)";
			$SQL = $painel_geral->prepare($SQL);
			$SQL->bindParam(':tipo', $TipoArquivo, PDO::PARAM_STR);
			$SQL->bindParam(':local', $explode[$i], PDO::PARAM_STR);
			$SQL->bindParam(':data', $DataArquivo, PDO::PARAM_STR);
			$SQL->bindParam(':size', $TamanhoArquivo, PDO::PARAM_STR);
			$SQL->execute(); 
			
		}
	}
		
		
		if(empty($SQL)){
			echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
		}
		else{
			echo MensagemAlerta($_TRA['sucesso'], "Atualização do backup realizado com sucesso!", "success", "index.php?p=backup-automatizado");
		}
				
}
		
}else{
		echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>