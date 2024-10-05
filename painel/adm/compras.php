<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
$AcessoUser = InfoUser(3);
$CadUser = InfoUser(2);

//Pagamentos
$PrePagoSessao = empty($_SESSION['PrePago']) ? "N" : $_SESSION['PrePago'];

if( ($AcessoUser == 2) && ($PrePagoSessao == "S") || ($AcessoUser == 3) || ($AcessoUser == 4) ){

$SQLPagSeguro = "SELECT comprador, CadUser, StatusTransacao, data, Referencia FROM pagseguro WHERE comprador = :comprador";
$SQLPagSeguro = $painel_geral->prepare($SQLPagSeguro);
$SQLPagSeguro->bindParam(':comprador', $CadUser, PDO::PARAM_STR);
$SQLPagSeguro->execute();

$SQLPay = "SELECT comprador, CadUser, payment_status, data, item_number FROM paypal WHERE comprador = :comprador";
$SQLPay = $painel_geral->prepare($SQLPay);
$SQLPay->bindParam(':comprador', $CadUser, PDO::PARAM_STR);
$SQLPay->execute();

$SQLMercado = "SELECT comprador, CadUser, payment_status, data, item_number FROM mercadopago WHERE comprador = :comprador";
$SQLMercado = $painel_geral->prepare($SQLMercado);
$SQLMercado->bindParam(':comprador', $CadUser, PDO::PARAM_STR);
$SQLMercado->execute();
?>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                	<li><?php echo $_TRA['Pagamentos']; ?></li>
                    <li class="active"><?php echo $_TRA['mco']; ?></li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="page-title">                    
          <h2><span class="fa fa-credit-card"></span> <?php echo $_TRA['mco']; ?></h2>
          </div>
                <!-- END PAGE TITLE -->   
 
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">                
                
                    <div class="row">
                        <div class="col-md-12">
                        
                        <div class="panel panel-danger">
                                <div class="panel-heading">
                                    <ul class="panel-controls">
                                        <li><a href="#" class="panel-fullscreen"><span class="fa fa-expand"></span></a></li>
                                        <li class="dropdown">
                                            <a href="#" class="dropdown-toggle" data-toggle="dropdown" aria-expanded="false"><span class="fa fa-cog"></span></a>                                            
                                            <ul class="dropdown-menu">
                                                <li><a href="#" class="panel-collapse"><span class="fa fa-angle-down"></span> <?php echo $_TRA['esconder']; ?></a></li>
                                                <li><a href="#" class="panel-refresh"><span class="fa fa-refresh"></span> <?php echo $_TRA['atualizar']; ?></a></li>
                                            </ul>                                        
                                        </li>
                                    </ul>
                                </div>
                                <div class="panel-body">
                                                                
                                    <div class="table-responsive">
                               <table id="Tabela" class="table datatable">
                               <thead>
                               		<tr>
                                        <th width="100"><?php echo $_TRA['Comprador']; ?></th>
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
                                        	<td>".$LnPag['comprador']."</td>
                                        	<td>PagSeguro</td>
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
                                        	<td>".$LnPag['comprador']."</td>
                                        	<td>PayPal</td>
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
                                        	<td>".$LnPag['comprador']."</td>
                                        	<td>MercadoPago</td>
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
										?>
                                            </tbody>
                                            
                                        </table>
                                    </div>
                                </div>                             
                            </div>



                        </div>
                    </div>                                
                    
                </div>
                <!-- PAGE CONTENT WRAPPER -->      
        

		<div id="StatusGeral"></div>        
<!-- START SCRIPTS -->
        <!-- START PLUGINS -->
        <script type="text/javascript" src="js/plugins/jquery/jquery.min.js"></script>
        <script type="text/javascript" src="js/plugins/jquery/jquery-ui.min.js"></script>
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap.min.js"></script>  
        <!-- END PLUGINS -->

        <!-- START THIS PAGE PLUGINS-->        
        <script type='text/javascript' src='js/plugins/icheck/icheck.min.js'></script>
        <script type="text/javascript" src="js/plugins/mcustomscrollbar/jquery.mCustomScrollbar.min.js"></script>  
        <script type='text/javascript' src='js/plugins/maskedinput/jquery.maskedinput.min.js'></script>  
        <script type="text/javascript" src="js/plugins/datatables/jquery.dataTables.min.js"></script>
        <script type="text/javascript" src="js/DataTables<?php echo Idioma(2); ?>.js"></script>  
        
        <!-- END THIS PAGE PLUGINS-->        

        <!-- START TEMPLATE -->
        <?php include_once("js/settings".Idioma(2).".php"); ?> 
        <script type="text/javascript" src="js/plugins.js"></script>        
        <script type="text/javascript" src="js/actions.js"></script>
        <!-- END TEMPLATE -->
        
    <!-- END SCRIPTS -->    
<?php
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>