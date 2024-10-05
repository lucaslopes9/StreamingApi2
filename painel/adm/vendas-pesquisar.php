<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
$AcessoUser = InfoUser(3);

//Pagamentos
$Coluna_16 = array('PagamentoPagSeguro', 'PagamentoPayPal', 'PagamentoMercadoPago', 'PagamentoContaBancaria');
$VerificarAcesso_16 = VerificarAcesso('pagamentos', $Coluna_16);
$PagamentoPagSeguro = $VerificarAcesso_16[0];
$PagamentoPayPal = $VerificarAcesso_16[1];
$PagamentoMercadoPago = $VerificarAcesso_16[2];
$PagamentoContaBancaria = $VerificarAcesso_16[3];

if( ($PagamentoPagSeguro == 'S') || ($PagamentoPayPal == 'S') || ($PagamentoMercadoPago == 'S') || ($PagamentoContaBancaria == 'S') ){ 

if( ($AcessoUser == 1) || ($AcessoUser == 2) ){
	
$caduser = (isset($_POST['caduser'])) ? $_POST['caduser'] : '';
$rev = (isset($_POST['rev'])) ? $_POST['rev'] : '';
$Metodo = (isset($_POST['Metodo'])) ? $_POST['Metodo'] : '';

if($rev == "S"){
	$CadUser = ArvoreAdminRev($caduser);
	$CadUser[] = $caduser;
	$CadUser = implode(',', $CadUser);
}else{
	$CadUser = InfoUser(2);
}

if( ($Metodo == "PagSeguro") || ($Metodo == "T") ){
$SQLPagSeguro = "SELECT comprador, CadUser, StatusTransacao, data, Referencia FROM pagseguro WHERE FIND_IN_SET(CadUser,:CadUser)";
$SQLPagSeguro = $painel_geral->prepare($SQLPagSeguro);
$SQLPagSeguro->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQLPagSeguro->execute();
}

if( ($Metodo == "PayPal") || ($Metodo == "T") ){
$SQLPay = "SELECT comprador, CadUser, payment_status, data, item_number FROM paypal WHERE FIND_IN_SET(CadUser,:CadUser)";
$SQLPay = $painel_geral->prepare($SQLPay);
$SQLPay->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQLPay->execute();
}

if( ($Metodo == "MercadoPago") || ($Metodo == "T") ){
$SQLMercado = "SELECT comprador, CadUser, payment_status, data, item_number FROM mercadopago WHERE FIND_IN_SET(CadUser,:CadUser)";
$SQLMercado = $painel_geral->prepare($SQLMercado);
$SQLMercado->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQLMercado->execute();
}
?>

                <!-- PAGE CONTENT WRAPPER -->
                <table id="Tabela" class="table datatable">
                               <thead>
                               		<tr>
                                    	<th width="100"><?php echo $_TRA['Vendedor']; ?></th>
                                        <th><?php echo $_TRA['Comprador']; ?></th>
                                        <th><?php echo $_TRA['Metodo']; ?></th>
                                        <th><?php echo $_TRA['Status']; ?></th>
                                        <th><?php echo $_TRA['Valor']; ?></th>
                                        <th><?php echo $_TRA['Plano']; ?></th>
                                        <th><?php echo $_TRA['Perfil']; ?></th>
                                        <th><?php echo $_TRA['conexao']; ?></th>
                                        <th><?php echo $_TRA['Data']; ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                        <?php
								if( ($Metodo == "PagSeguro") || ($Metodo == "T") ){
								while($LnPag = $SQLPagSeguro->fetch()){
									
								$SQLComprar = "SELECT dias, valor, perfil, conexao, PrePago, Quantidade FROM comprar WHERE referencia = :referencia";
								$SQLComprar = $painel_geral->prepare($SQLComprar);
								$SQLComprar->bindParam(':referencia', $LnPag['Referencia'], PDO::PARAM_STR);
								$SQLComprar->execute();
								$LnComprar = $SQLComprar->fetch();
								$valor = number_format($LnComprar['valor'], 2, ',', '');
								$diaSSS = $LnComprar['dias'] > 1 ? $_TRA['dias'] : $_TRA['dia'];
								$CotaSSS = $LnComprar['Quantidade'] > 1 ? $_TRA['ccotas'] : $_TRA['ccota'];
								
								if($LnComprar['PrePago'] == "S"){
									$Plano = "".$LnComprar['dias']." ".$diaSSS." (".$LnComprar['Quantidade']." ".$CotaSSS.")";
								}
								else{
									$Plano = "".$LnComprar['dias']." ".$diaSSS."";
								}
																					
										echo "
                                        <tr>
											<td>".$LnPag['CadUser']."</td>
                                        	<td>".$LnPag['comprador']."</td>
                                        	<td>".$_TRA['PagSeguro']."</td>
											<td>".StatusPagSeguro($LnPag['StatusTransacao'])."</td>
											<td>".VerRepDin()." ".$valor."</td>
											<td>".$Plano."</td>
											<td>".SelecionarPerfil($LnComprar['perfil'])."</td>
											<td>".$LnComprar['conexao']."</td>
											<td>".ConverterDataTime($LnPag['data'])."</td>
											";
											
									echo "</tr>
										";
										}
								}
								
								if( ($Metodo == "PayPal") || ($Metodo == "T") ){
								while($LnPag = $SQLPay->fetch()){
									
								$SQLComprar = "SELECT dias, valor, perfil, conexao, PrePago, Quantidade FROM comprar WHERE referencia = :referencia";
								$SQLComprar = $painel_geral->prepare($SQLComprar);
								$SQLComprar->bindParam(':referencia', $LnPag['item_number'], PDO::PARAM_STR);
								$SQLComprar->execute();
								$LnComprar = $SQLComprar->fetch();
								$valor = number_format($LnComprar['valor'], 2, ',', '');
								$diaSSS = $LnComprar['dias'] > 1 ? $_TRA['dias'] : $_TRA['dia'];
								$CotaSSS = $LnComprar['Quantidade'] > 1 ? $_TRA['ccotas'] : $_TRA['ccota'];
								
								if($LnComprar['PrePago'] == "S"){
									$Plano = "".$LnComprar['dias']." ".$diaSSS." (".$LnComprar['Quantidade']." ".$CotaSSS.")";
								}
								else{
									$Plano = "".$LnComprar['dias']." ".$diaSSS."";
								}
																					
										echo "
                                        <tr>
											<td>".$LnPag['CadUser']."</td>
                                        	<td>".$LnPag['comprador']."</td>
                                        	<td>".$_TRA['PayPal']."</td>
											<td>".StatusPaypalMercadoPago($LnPag['payment_status'])."</td>
											<td>".VerRepDin()." ".$valor."</td>
											<td>".$Plano."</td>
											<td>".SelecionarPerfil($LnComprar['perfil'])."</td>
											<td>".$LnComprar['conexao']."</td>
											<td>".ConverterDataTime($LnPag['data'])."</td>
											";
											
									echo "</tr>
										";
										}
								}
								
								if( ($Metodo == "MercadoPago") || ($Metodo == "T") ){
								while($LnPag = $SQLMercado->fetch()){
									
								$SQLComprar = "SELECT dias, valor, perfil, conexao, PrePago, Quantidade FROM comprar WHERE referencia = :referencia";
								$SQLComprar = $painel_geral->prepare($SQLComprar);
								$SQLComprar->bindParam(':referencia', $LnPag['item_number'], PDO::PARAM_STR);
								$SQLComprar->execute();
								$LnComprar = $SQLComprar->fetch();
								$valor = number_format($LnComprar['valor'], 2, ',', '');
								$diaSSS = $LnComprar['dias'] > 1 ? $_TRA['dias'] : $_TRA['dia'];
								$CotaSSS = $LnComprar['Quantidade'] > 1 ? $_TRA['ccotas'] : $_TRA['ccota'];
								
								if($LnComprar['PrePago'] == "S"){
									$Plano = "".$LnComprar['dias']." ".$diaSSS." (".$LnComprar['Quantidade']." ".$CotaSSS.")";
								}
								else{
									$Plano = "".$LnComprar['dias']." ".$diaSSS."";
								}
																					
										echo "
                                        <tr>
											<td>".$LnPag['CadUser']."</td>
                                        	<td>".$LnPag['comprador']."</td>
                                        	<td>".$_TRA['MercadoPago']."</td>
											<td>".StatusPaypalMercadoPago($LnPag['payment_status'])."</td>
											<td>".VerRepDin()." ".$valor."</td>
											<td>".$Plano."</td>
											<td>".SelecionarPerfil($LnComprar['perfil'])."</td>
											<td>".$LnComprar['conexao']."</td>
											<td>".ConverterDataTime($LnPag['data'])."</td>
											";
											
									echo "</tr>
										";
										}
								}
										?>
                                            </tbody>
                                        </table>
        
    <!-- START THIS PAGE PLUGINS-->        
        <script type="text/javascript" src="js/plugins/datatables/jquery.dataTables.min.js"></script>
        <script type="text/javascript" src="js/DataTables<?php echo Idioma(2); ?>.js"></script>  
        <!-- END THIS PAGE PLUGINS-->        

<?php
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>