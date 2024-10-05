<?php
	set_time_limit(0);
	set_include_path('ssh');
	include('ssh/Net/SFTP.php');
	include("conexao.php");
	include_once("functions.php");
	include_once(Idioma(1));
	global $_TRA;
		
	$BackupAgora = (isset($_POST['id'])) ? $_POST['id'] : '';
	
	$SqlStatusServer = "SELECT * FROM backup_automatizado";
	$SqlStatusServer = $painel_geral->prepare($SqlStatusServer);
	$SqlStatusServer->execute();
	$LnStatusServer = $SqlStatusServer->fetch();
	
	$EnviarStatus = $LnStatusServer['status'];
	$tempo = $LnStatusServer['tempo'];
	$horario = $LnStatusServer['horario'];
	$server = $LnStatusServer['server'];
	
	$DataAtual = time();
	$pasta = "/home/cs/";
	
	//Verifica se o Backup está ativado
	if($EnviarStatus != "S"){
		echo MensagemAlerta($_TRA['erro'], $_TRA['nfprobnesa'], "danger");
		exit;
	}
	
	if(empty($tempo)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['nfprobnest'], "danger");
		exit;
	}
	
	if(empty($horario)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['nfprobnesh'], "danger");
		exit;
	}
	
	if(empty($server)){
		echo MensagemAlerta($_TRA['erro'], 'Configure um servidor para backup!', "danger");
		exit;
	}
	
	if( ($BackupAgora != "BackupAgora") ){
		if($DataAtual < $horario){
			exit;
		}
	}
	
	$banco_backup_user = "backup/".$_MDouglas['painel_user']."_".$DataAtual.".sql";
	$banco_backup_user_base = "".$_MDouglas['painel_user']."_".$DataAtual.".sql";
	$command = "mysqldump -u".$_MDouglas['usuario']." -p".$_MDouglas['senha']." ".$_MDouglas['painel_user']." > ".$banco_backup_user."";
	exec($command, $result, $output);
	if($output != 0) {
		echo MensagemAlerta("Erro", "Ocorreu um erro ao fazer backup do banco de dados USER", "danger");
		exit;
	}
	
	$banco_backup_acessos = "backup/".$_MDouglas['painel_acessos']."_".$DataAtual.".sql";
	$banco_backup_acessos_base = "".$_MDouglas['painel_acessos']."_".$DataAtual.".sql";
	$command = "mysqldump -u".$_MDouglas['usuario']." -p".$_MDouglas['senha']." ".$_MDouglas['painel_acessos']." > ".$banco_backup_acessos."";
	exec($command,$result, $output);
	if($output != 0) {
		echo MensagemAlerta("Erro", "Ocorreu um erro ao fazer backup do banco de dados ACESSOS", "danger");
		exit;
	}
	
	$banco_backup_geral = "backup/".$_MDouglas['painel_geral']."_".$DataAtual.".sql";
	$banco_backup_geral_base = "".$_MDouglas['painel_geral']."_".$DataAtual.".sql";
	$command = "mysqldump -u".$_MDouglas['usuario']." -p".$_MDouglas['senha']." ".$_MDouglas['painel_geral']." > ".$banco_backup_geral."";
	exec($command,$result, $output);
	if($output != 0) {
		echo MensagemAlerta("Erro", "Ocorreu um erro ao fazer backup do banco de dados GERAL", "danger");
		exit;
	}

	$SQLServer = "SELECT * FROM server WHERE id = :id";
	$SQLServer = $painel_geral->prepare($SQLServer);
	$SQLServer->bindParam(':id', $server, PDO::PARAM_STR);
	$SQLServer->execute();
	$LnServer = $SQLServer->fetch();
	$ip = my_decrypt($LnServer['ip']);
	$porta = my_decrypt($LnServer['porta']);
	$user = my_decrypt($LnServer['user']);
	$senha = my_decrypt($LnServer['senha']);
	
	$ssh = new Net_SFTP($ip, $porta);
	if (!$ssh->login($user, $senha)) {
   		echo MensagemAlerta("Erro", "Dados do Servidor de Backup inválido, não foi possível estabelecer a conexão!", "danger");
		exit;
	}
	
	$ssh->mkdir($pasta);
	$ssh->put($pasta.$banco_backup_user_base, $banco_backup_user, NET_SFTP_LOCAL_FILE);
	$ssh->put($pasta.$banco_backup_acessos_base, $banco_backup_acessos, NET_SFTP_LOCAL_FILE);
	$ssh->put($pasta.$banco_backup_geral_base, $banco_backup_geral, NET_SFTP_LOCAL_FILE);

	$TamanhoUser = filesize($banco_backup_user);
	$TamanhoAcessos = filesize($banco_backup_acessos);
	$TamanhoGeral = filesize($banco_backup_geral);
	
	//User
	$tipo = "Usuário";
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
	$SQL->bindParam(':tipo', $tipo, PDO::PARAM_STR);
	$SQL->bindParam(':local', $banco_backup_user_base, PDO::PARAM_STR);
	$SQL->bindParam(':data', $DataAtual, PDO::PARAM_STR);
	$SQL->bindParam(':size', $TamanhoUser, PDO::PARAM_STR);
	$SQL->execute(); 

	//Acessos
	$tipo = "Acessos";
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
	$SQL->bindParam(':tipo', $tipo, PDO::PARAM_STR);
	$SQL->bindParam(':local', $banco_backup_acessos_base, PDO::PARAM_STR);
	$SQL->bindParam(':data', $DataAtual, PDO::PARAM_STR);
	$SQL->bindParam(':size', $TamanhoAcessos, PDO::PARAM_STR);
	$SQL->execute(); 

	//Geral
	$tipo = "Geral";
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
	$SQL->bindParam(':tipo', $tipo, PDO::PARAM_STR);
	$SQL->bindParam(':local', $banco_backup_geral_base, PDO::PARAM_STR);
	$SQL->bindParam(':data', $DataAtual, PDO::PARAM_STR);
	$SQL->bindParam(':size', $TamanhoGeral, PDO::PARAM_STR);
	$SQL->execute(); 

	@unlink($banco_backup_user);
	@unlink($banco_backup_acessos);
	@unlink($banco_backup_geral);

	$HorarioInserir = time() + (3600 * $tempo);
	$SQLBa = "UPDATE backup_automatizado SET
			horario = :horario";
	$SQLBa = $painel_geral->prepare($SQLBa);                                  
	$SQLBa->bindValue(':horario', $HorarioInserir); 
	$SQLBa->execute();

	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], "Backup Automatizado feito com sucesso!", "success", "index.php?p=backup-automatizado");
	}

?>