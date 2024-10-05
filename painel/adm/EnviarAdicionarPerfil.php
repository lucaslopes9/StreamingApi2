<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('PerfilAdicionar');
$VerificarAcesso = VerificarAcesso('perfil', $ColunaAcesso);
$PerfilAdicionar = $VerificarAcesso[0];
 
if($PerfilAdicionar == 'S'){

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
	
	$SQLPainel = "SELECT nome FROM painel";
	$SQLPainel = $painel_geral->prepare($SQLPainel);
	$SQLPainel->execute();
	$TotalPainel = count($SQLPainel->fetchAll());
	
	$SQLImagem = "SELECT id, img FROM perfil_icone";
	$SQLImagem = $painel_geral->prepare($SQLImagem);
	$SQLImagem->execute();
	$TotalImagem = count($SQLImagem->fetchAll());
	
	$EditarTipo = (isset($_POST['EditarTipo'])) ? $_POST['EditarTipo'] : '';
	$EditarCSP = (isset($_POST['EditarCSP'])) ? $_POST['EditarCSP'] : '';
	$EditarImagem = (isset($_POST['EditarImagem'])) ? $_POST['EditarImagem'] : '';
	$EditarNome = (isset($_POST['EditarNome'])) ? $_POST['EditarNome'] : '';
	$EditarValorCSP = $_POST['EditarValorCSP'];
	$EditarUrl = (isset($_POST['EditarUrl'])) ? $_POST['EditarUrl'] : '';
	$EditarPorta = (isset($_POST['EditarPorta'])) ? $_POST['EditarPorta'] : '';

	if($TotalPainel < 1){
		echo MensagemAlerta($_TRA['erro'], $_TRA['paupnpasc']."<a href=\"index.php?p=csp\" style=\"color:#FFF;\"><i>".$_TRA['caqui']."</i></a>.", "danger");
	}
	elseif($TotalImagem < 1){
		echo MensagemAlerta($_TRA['erro'], $_TRA['papnpaipp'], "danger");
	}
	elseif(empty($EditarCSP)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['secsuco'], "danger");
	}
	elseif(empty($EditarTipo)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['teuco'], "danger");
	}
	elseif(empty($EditarImagem)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['imguco'], "danger");
	}
	elseif(empty($EditarNome)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['nuco'], "danger");
	}
	elseif(empty($EditarValorCSP)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['vncuco'], "danger");
	}
	elseif( substr_count($EditarValorCSP, " ") > 0){
		echo MensagemAlerta($_TRA['erro'], $_TRA['vncncebuco'], "danger");
	}
	elseif( (substr_count($EditarValorCSP, "[") > 0) || (substr_count($EditarValorCSP, "]") > 0) ){
		echo MensagemAlerta($_TRA['erro'], $_TRA['vncnpcc'], "danger");
	}
	elseif(empty($EditarUrl)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['urluco'], "danger");
	}
	elseif(empty($EditarPorta)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['puco'], "danger");
	}
	elseif(is_numeric($EditarPorta) == false){
		echo MensagemAlerta($_TRA['erro'], $_TRA['pordcan'], "danger");
	}
	else{
	
	$EditarValorCSP = "[".$EditarValorCSP."]";
		
	$id_user = InfoUser(1);
	$usuario = InfoUser(2);
	$SQLUser = "SELECT perfil FROM admin WHERE id = :id AND usuario = :usuario";
	$SQLUser = $painel_user->prepare($SQLUser);
	$SQLUser->bindParam(':id', $id_user, PDO::PARAM_INT);
	$SQLUser->bindParam(':usuario', $usuario, PDO::PARAM_STR);
	$SQLUser->execute();
	$LnUser = $SQLUser->fetch();
	$perfil = $LnUser['perfil'];
	
	if(empty($perfil)){
		$PerfilAtualizar = $EditarValorCSP;
	}
	else{
		$VerificarPerfil = VerificarPerfil($EditarValorCSP);
		if($VerificarPerfil > 0){
			$PerfilAtualizar = $perfil;
		}
		else{
			$PerfilAtualizar = $perfil.$EditarValorCSP;
		}
	}

	$SQLAtu = "UPDATE admin SET
			perfil = :perfil
            WHERE id = :id AND usuario = :usuario";
	$SQLAtu = $painel_user->prepare($SQLAtu);
	$SQLAtu->bindParam(':perfil', $PerfilAtualizar, PDO::PARAM_STR); 
	$SQLAtu->bindParam(':id', $id_user, PDO::PARAM_INT); 
	$SQLAtu->bindParam(':usuario', $usuario, PDO::PARAM_STR); 
	$SQLAtu->execute(); 
		
	$SQL = "INSERT INTO perfil (
			painel,
            imagem,
            nome,
			valorcsp,
			url,
			porta,
			tipo
            ) VALUES (
            :painel,
            :imagem,
            :nome,
			:valorcsp,
			:url,
			:porta,
			:tipo
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':painel', $EditarCSP, PDO::PARAM_INT);
	$SQL->bindParam(':imagem', $EditarImagem, PDO::PARAM_INT);
	$SQL->bindParam(':nome', $EditarNome, PDO::PARAM_STR);
	$SQL->bindParam(':valorcsp', $EditarValorCSP, PDO::PARAM_STR);
	$SQL->bindParam(':url', $EditarUrl, PDO::PARAM_STR);
	$SQL->bindParam(':porta', $EditarPorta, PDO::PARAM_INT);
	$SQL->bindParam(':tipo', $EditarTipo, PDO::PARAM_STR);
	$SQL->execute(); 
	
	if(empty($SQL)){
		echo MensagemAlerta($_TRA['erro'], $_TRA['erropro'], "danger");
	}
	else{
		echo MensagemAlerta($_TRA['sucesso'], $_TRA['alcs'], "success", "index.php?p=perfil");
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