<?php
	set_include_path('ssh');
	include('ssh/Net/SFTP.php');
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
		
	$SQLArquivos = "SELECT local, tipo FROM arquivo_backup WHERE id = :id";
	$SQLArquivos = $painel_geral->prepare($SQLArquivos);
	$SQLArquivos->bindParam(':id', $id, PDO::PARAM_STR);
	$SQLArquivos->execute();
	$LnArquivos = $SQLArquivos->fetch();
	$local = $LnArquivos['local'];
    $tipo = $LnArquivos['tipo'];
		
	if($tipo == "Usuário"){
		$banco_restaurar = $_MDouglas['painel_user'];
	}
	elseif($tipo == "Acessos"){
		$banco_restaurar = $_MDouglas['painel_acessos'];
	}
	elseif($tipo == "Geral"){
		$banco_restaurar = $_MDouglas['painel_geral'];
	}
	else{
		echo MensagemAlerta($_TRA['erro'], "Ocorreu um erro ao restaurar o banco de dados!", "danger");
		exit;
	}
		
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
	
	$ssh = new Net_SFTP($ip, $porta);
	if (!$ssh->login($user, $senha)) {
   		echo MensagemAlerta("Erro", "Dados do Servidor de Backup inválido, não foi possível estabelecer a conexão!", "danger");
		exit;
	}
		
	$ssh->get("/home/cs/".$local, "backup/".$local."");
		
	$command = "mysql -u".$_MDouglas['usuario']." -p".$_MDouglas['senha']." -h localhost ".$banco_restaurar." < ".dirname( __FILE__ )."/backup/".$local."";
	exec($command, $result, $output);
		
	@unlink(dirname( __FILE__ )."/backup/".$local);	
	if($output != 0) {
		echo MensagemAlerta($_TRA['erro'], "Ocorreu um erro ao restaurar o banco de dados!", "danger");
		exit;
	}
	else{
		echo MensagemAlerta("Sucesso", "Banco de Dados restaurado com sucesso!", "success");	
	}
		

		
	}
		
}else{
		echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>