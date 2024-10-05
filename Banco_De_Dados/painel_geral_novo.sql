/*
Navicat MySQL Data Transfer

Source Server         : painel2
Source Server Version : 50505
Source Host           : 51.222.140.196:3306
Source Database       : painel_geral

Target Server Type    : MYSQL
Target Server Version : 50505
File Encoding         : 65001

Date: 2023-08-04 12:54:27
*/

SET FOREIGN_KEY_CHECKS=0;
-- ----------------------------
-- Table structure for `arquivo_backup`
-- ----------------------------
DROP TABLE IF EXISTS `arquivo_backup`;
CREATE TABLE `arquivo_backup` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tipo` varchar(250) DEFAULT NULL,
  `local` mediumtext DEFAULT NULL,
  `data` varchar(250) DEFAULT NULL,
  `size` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of arquivo_backup
-- ----------------------------

-- ----------------------------
-- Table structure for `backup`
-- ----------------------------
DROP TABLE IF EXISTS `backup`;
CREATE TABLE `backup` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `status` varchar(11) NOT NULL DEFAULT 'N',
  `tempo` varchar(11) DEFAULT NULL,
  `horario` varchar(250) DEFAULT NULL,
  `email` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of backup
-- ----------------------------
INSERT INTO `backup` VALUES ('1', 'N', '24', '1691249801', '');

-- ----------------------------
-- Table structure for `backup_automatizado`
-- ----------------------------
DROP TABLE IF EXISTS `backup_automatizado`;
CREATE TABLE `backup_automatizado` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `status` varchar(11) NOT NULL DEFAULT 'N',
  `tempo` varchar(250) NOT NULL,
  `horario` varchar(250) NOT NULL,
  `server` varchar(250) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of backup_automatizado
-- ----------------------------

-- ----------------------------
-- Table structure for `bancoemail`
-- ----------------------------
DROP TABLE IF EXISTS `bancoemail`;
CREATE TABLE `bancoemail` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `email` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=522 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of bancoemail
-- ----------------------------

-- ----------------------------
-- Table structure for `bit`
-- ----------------------------
DROP TABLE IF EXISTS `bit`;
CREATE TABLE `bit` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `usuario` varchar(250) DEFAULT NULL,
  `api` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of bit
-- ----------------------------

-- ----------------------------
-- Table structure for `captcha`
-- ----------------------------
DROP TABLE IF EXISTS `captcha`;
CREATE TABLE `captcha` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `status` varchar(11) NOT NULL DEFAULT 'S',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of captcha
-- ----------------------------
INSERT INTO `captcha` VALUES ('1', 'N');

-- ----------------------------
-- Table structure for `comprar`
-- ----------------------------
DROP TABLE IF EXISTS `comprar`;
CREATE TABLE `comprar` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `comprador` varchar(250) DEFAULT NULL,
  `referencia` varchar(250) DEFAULT NULL,
  `dias` varchar(250) DEFAULT NULL,
  `valor` varchar(250) DEFAULT NULL,
  `perfil` text DEFAULT NULL,
  `conexao` varchar(250) DEFAULT NULL,
  `PrePago` varchar(11) NOT NULL DEFAULT 'N',
  `Quantidade` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of comprar
-- ----------------------------

-- ----------------------------
-- Table structure for `config_suporte`
-- ----------------------------
DROP TABLE IF EXISTS `config_suporte`;
CREATE TABLE `config_suporte` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `SuportePaginacao` int(11) DEFAULT 10,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of config_suporte
-- ----------------------------

-- ----------------------------
-- Table structure for `contabancaria`
-- ----------------------------
DROP TABLE IF EXISTS `contabancaria`;
CREATE TABLE `contabancaria` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `banco` varchar(250) DEFAULT NULL,
  `tipo` varchar(11) DEFAULT 'C',
  `agencia` varchar(250) DEFAULT NULL,
  `operacao` varchar(250) DEFAULT NULL,
  `conta` varchar(250) DEFAULT NULL,
  `favorecido` varchar(250) DEFAULT NULL,
  `bloqueado` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of contabancaria
-- ----------------------------

-- ----------------------------
-- Table structure for `contamercadopago`
-- ----------------------------
DROP TABLE IF EXISTS `contamercadopago`;
CREATE TABLE `contamercadopago` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `clientid` varchar(250) DEFAULT NULL,
  `clientsecret` varchar(250) DEFAULT NULL,
  `bloqueado` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of contamercadopago
-- ----------------------------

-- ----------------------------
-- Table structure for `contapagseguro`
-- ----------------------------
DROP TABLE IF EXISTS `contapagseguro`;
CREATE TABLE `contapagseguro` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `email` varchar(250) DEFAULT NULL,
  `token` varchar(250) DEFAULT NULL,
  `bloqueado` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of contapagseguro
-- ----------------------------

-- ----------------------------
-- Table structure for `contapaypal`
-- ----------------------------
DROP TABLE IF EXISTS `contapaypal`;
CREATE TABLE `contapaypal` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `email` varchar(250) DEFAULT NULL,
  `senha` varchar(250) DEFAULT NULL,
  `bloqueado` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of contapaypal
-- ----------------------------

-- ----------------------------
-- Table structure for `cupom`
-- ----------------------------
DROP TABLE IF EXISTS `cupom`;
CREATE TABLE `cupom` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `CriadoEm` varchar(250) DEFAULT NULL,
  `Cupom` varchar(250) DEFAULT NULL,
  `UserDescontar` varchar(250) DEFAULT NULL,
  `UserDescontarEm` varchar(250) DEFAULT NULL,
  `dias` varchar(250) DEFAULT NULL,
  `perfil` mediumtext DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of cupom
-- ----------------------------

-- ----------------------------
-- Table structure for `email_adicionar`
-- ----------------------------
DROP TABLE IF EXISTS `email_adicionar`;
CREATE TABLE `email_adicionar` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `servidor` varchar(250) DEFAULT NULL,
  `exibicao` varchar(250) DEFAULT NULL,
  `email` varchar(250) DEFAULT NULL,
  `usuario` varchar(250) DEFAULT NULL,
  `senha` varchar(250) DEFAULT NULL,
  `SMTPSecure` varchar(250) DEFAULT NULL,
  `Host` varchar(250) DEFAULT NULL,
  `Port` int(11) DEFAULT NULL,
  `bloqueado` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=103 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of email_adicionar
-- ----------------------------

-- ----------------------------
-- Table structure for `email_modelo`
-- ----------------------------
DROP TABLE IF EXISTS `email_modelo`;
CREATE TABLE `email_modelo` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `tipo` varchar(250) DEFAULT 'Painel',
  `assunto` varchar(250) DEFAULT NULL,
  `mensagem` longtext DEFAULT NULL,
  `bloqueado` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=342 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of email_modelo
-- ----------------------------
INSERT INTO `email_modelo` VALUES ('1', 'admin', 'Painel', 'Renovação', '<span style=\"color: rgb(121, 121, 121); font-size: 13px; background-color: rgb(249, 249, 249);\">Olá senhor(a), [NMCLIENTE].</span><br style=\"color: rgb(121, 121, 121); font-size: 13px;\"><br style=\"color: rgb(121, 121, 121); font-size: 13px;\"><span style=\"color: rgb(121, 121, 121); font-size: 13px; background-color: rgb(249, 249, 249);\">Venho lhe informa que seu login,&nbsp; [LGCLIENTE] foi renovado com sucesso, proxima data de Vencimento: [VCCLIENTE]</span>', 'N');
INSERT INTO `email_modelo` VALUES ('2', 'admin', 'Painel', 'Login Teste', '<p>Olá senhor(a), [NMCLIENTE].<br><br>segue a baixo os dados de Seu login Teste:<br><br>Login do Cliente: [LGCLIENTE]<br>Senha do Cliente: [SNCLIENTE]<br>Data de Vencimento: [VCCLIENTE]<br>URL do Perfil:&nbsp;<br>Porta do Perfil CLAROTV: 30000 ou 1900</p><p>Deskeys: 0102030405060708091011121314<br><br></p>', 'N');
INSERT INTO `email_modelo` VALUES ('3', 'admin', 'Painel', 'Vencimento	', '<span style=\"color: rgb(121, 121, 121); font-size: 13px; background-color: rgb(249, 249, 249);\">Olá senhor(a), [NMCLIENTE].</span><br style=\"color: rgb(121, 121, 121); font-size: 13px;\"><br style=\"color: rgb(121, 121, 121); font-size: 13px;\"><span style=\"color: rgb(121, 121, 121); font-size: 13px; background-color: rgb(249, 249, 249);\">Venho lhe informa o vencimento de seu login:</span><br style=\"color: rgb(121, 121, 121); font-size: 13px;\"><br style=\"color: rgb(121, 121, 121); font-size: 13px;\"><br style=\"color: rgb(121, 121, 121); font-size: 13px;\"><span style=\"color: rgb(121, 121, 121); font-size: 13px; background-color: rgb(249, 249, 249);\">Data de Vencimento: [VCCLIENTE]</span>', 'N');
INSERT INTO `email_modelo` VALUES ('4', 'admin', 'Painel', 'Dados	', 'Olá senhor(a), [NMCLIENTE].<br><br>segue a baixo os dados de seu login:<br><br>Login do Cliente: [LGCLIENTE]<br>Senha do Cliente: [SNCLIENTE]<br>Data de Vencimento: [VCCLIENTE]<br><p>URL do Perfil:&nbsp;<br>Porta do Perfil CLAROTV: 30000 ou 1900</p>Deskeys: 0102030405060708091011121314', 'N');

-- ----------------------------
-- Table structure for `email_preferencias`
-- ----------------------------
DROP TABLE IF EXISTS `email_preferencias`;
CREATE TABLE `email_preferencias` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `DadosDeAcesso` int(11) DEFAULT NULL,
  `DadosDeAcessoTeste` int(11) DEFAULT NULL,
  `Vencimento` int(11) DEFAULT NULL,
  `Renovacao` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=83 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of email_preferencias
-- ----------------------------

-- ----------------------------
-- Table structure for `email_teste`
-- ----------------------------
DROP TABLE IF EXISTS `email_teste`;
CREATE TABLE `email_teste` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `email` varchar(250) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of email_teste
-- ----------------------------

-- ----------------------------
-- Table structure for `emailtemporario`
-- ----------------------------
DROP TABLE IF EXISTS `emailtemporario`;
CREATE TABLE `emailtemporario` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `email` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=105 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of emailtemporario
-- ----------------------------

-- ----------------------------
-- Table structure for `grupodeacesso`
-- ----------------------------
DROP TABLE IF EXISTS `grupodeacesso`;
CREATE TABLE `grupodeacesso` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `nome` varchar(250) DEFAULT NULL,
  `bloqueado` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=16 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of grupodeacesso
-- ----------------------------
INSERT INTO `grupodeacesso` VALUES ('1', 'admin', 'Revenda', 'N');

-- ----------------------------
-- Table structure for `leiaute`
-- ----------------------------
DROP TABLE IF EXISTS `leiaute`;
CREATE TABLE `leiaute` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `leiaute` int(11) DEFAULT NULL,
  `wall` varchar(250) DEFAULT NULL,
  `cabecalho` int(11) DEFAULT NULL,
  `barralateral` int(11) DEFAULT NULL,
  `scroll` int(11) DEFAULT NULL,
  `barradireita` int(11) DEFAULT NULL,
  `navpersonalizado` int(11) DEFAULT NULL,
  `alternarnav` int(11) DEFAULT NULL,
  `minimizar` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=690 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of leiaute
-- ----------------------------
INSERT INTO `leiaute` VALUES ('1', 'admin', '0', 'wall_8', '0', '1', '1', '0', '0', '0', 'N');

-- ----------------------------
-- Table structure for `liberarcomputador`
-- ----------------------------
DROP TABLE IF EXISTS `liberarcomputador`;
CREATE TABLE `liberarcomputador` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `gethostbyaddr` varchar(250) DEFAULT NULL,
  `computador` varchar(250) DEFAULT NULL,
  `ip` varchar(250) DEFAULT NULL,
  `codigo` varchar(250) DEFAULT NULL,
  `ativo` varchar(11) NOT NULL DEFAULT 'N',
  `data` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of liberarcomputador
-- ----------------------------

-- ----------------------------
-- Table structure for `mascaraurl`
-- ----------------------------
DROP TABLE IF EXISTS `mascaraurl`;
CREATE TABLE `mascaraurl` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `perfil` int(11) DEFAULT NULL,
  `nome` varchar(250) DEFAULT NULL,
  `url` varchar(250) DEFAULT NULL,
  `porta` varchar(250) DEFAULT NULL,
  `bloqueado` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of mascaraurl
-- ----------------------------

-- ----------------------------
-- Table structure for `mercadopago`
-- ----------------------------
DROP TABLE IF EXISTS `mercadopago`;
CREATE TABLE `mercadopago` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `comprador` varchar(250) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `payment_status` varchar(250) DEFAULT NULL,
  `item_number` varchar(250) DEFAULT NULL,
  `data` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of mercadopago
-- ----------------------------

-- ----------------------------
-- Table structure for `noticias`
-- ----------------------------
DROP TABLE IF EXISTS `noticias`;
CREATE TABLE `noticias` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `titulo` varchar(250) DEFAULT NULL,
  `noticia` longtext DEFAULT '',
  `pdata` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of noticias
-- ----------------------------

-- ----------------------------
-- Table structure for `pagseguro`
-- ----------------------------
DROP TABLE IF EXISTS `pagseguro`;
CREATE TABLE `pagseguro` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `comprador` varchar(250) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `TipoPagamento` varchar(250) DEFAULT NULL,
  `StatusTransacao` varchar(250) DEFAULT NULL,
  `Referencia` varchar(250) DEFAULT NULL,
  `data` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of pagseguro
-- ----------------------------

-- ----------------------------
-- Table structure for `painel`
-- ----------------------------
DROP TABLE IF EXISTS `painel`;
CREATE TABLE `painel` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nome` varchar(250) DEFAULT NULL,
  `url` varchar(250) DEFAULT NULL,
  `porta` int(11) DEFAULT NULL,
  `usuario` varchar(250) DEFAULT NULL,
  `senha` varchar(250) DEFAULT NULL,
  `protocolo` varchar(250) DEFAULT NULL,
  `maxserver` varchar(250) NOT NULL DEFAULT '1000',
  `block` varchar(11) NOT NULL DEFAULT 'N',
  `atualizar` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of painel
-- ----------------------------

-- ----------------------------
-- Table structure for `painel_config`
-- ----------------------------
DROP TABLE IF EXISTS `painel_config`;
CREATE TABLE `painel_config` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `senha` varchar(250) DEFAULT NULL,
  `deskeys` varchar(250) DEFAULT NULL,
  `ip` text DEFAULT NULL,
  `iplock` varchar(11) NOT NULL DEFAULT 'S',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of painel_config
-- ----------------------------
INSERT INTO `painel_config` VALUES ('1', '64897263', '0102030405060708091011121314', '', 'N');

-- ----------------------------
-- Table structure for `paypal`
-- ----------------------------
DROP TABLE IF EXISTS `paypal`;
CREATE TABLE `paypal` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `comprador` varchar(250) DEFAULT NULL,
  `CadUser` varchar(250) DEFAULT NULL,
  `payment_status` varchar(250) DEFAULT NULL,
  `item_number` varchar(250) DEFAULT NULL,
  `data` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of paypal
-- ----------------------------

-- ----------------------------
-- Table structure for `perfil`
-- ----------------------------
DROP TABLE IF EXISTS `perfil`;
CREATE TABLE `perfil` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `painel` int(11) DEFAULT NULL,
  `imagem` int(11) DEFAULT NULL,
  `nome` varchar(250) DEFAULT NULL,
  `valorcsp` varchar(250) DEFAULT NULL,
  `url` varchar(250) DEFAULT NULL,
  `porta` int(11) DEFAULT NULL,
  `tipo` varchar(250) NOT NULL DEFAULT 'SAT',
  `bloqueado` varchar(11) NOT NULL DEFAULT 'N',
  `verificar` varchar(11) NOT NULL DEFAULT 'S',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of perfil
-- ----------------------------

-- ----------------------------
-- Table structure for `perfil_icone`
-- ----------------------------
DROP TABLE IF EXISTS `perfil_icone`;
CREATE TABLE `perfil_icone` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nome` varchar(250) DEFAULT NULL,
  `img` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of perfil_icone
-- ----------------------------
INSERT INTO `perfil_icone` VALUES ('1', 'logo Claro', '1511843401_c27e8c41782e4d72d00676771ac592095ea22fa9.png');
INSERT INTO `perfil_icone` VALUES ('2', 'Logo SKY', '1522160351_7177860d2562d0ad08bf2078e81af1964cf18c92.png');
INSERT INTO `perfil_icone` VALUES ('3', 'Logo Oi', '1522160844_e5e03e2cf0beafe8197c69c56a8c6781fb66fad9.png');
INSERT INTO `perfil_icone` VALUES ('4', 'Logo Net', '1522160995_e89f88e86987b40f9f792a9ac56eb4022647d776.png');
INSERT INTO `perfil_icone` VALUES ('5', 'Logo Vivo', '1522161243_b1fd2ffae5e30449db90cc7e3956a0250c7ea220.png');

-- ----------------------------
-- Table structure for `planos`
-- ----------------------------
DROP TABLE IF EXISTS `planos`;
CREATE TABLE `planos` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `nomeplano` varchar(250) DEFAULT NULL,
  `tipoperfil` varchar(250) NOT NULL DEFAULT 'SAT',
  `tipoplano` varchar(250) DEFAULT 'N',
  `dias` varchar(250) DEFAULT NULL,
  `valor` varchar(250) DEFAULT NULL,
  `perfil` text DEFAULT NULL,
  `quantidade` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=28 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of planos
-- ----------------------------

-- ----------------------------
-- Table structure for `rede_social`
-- ----------------------------
DROP TABLE IF EXISTS `rede_social`;
CREATE TABLE `rede_social` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `facebook` mediumtext DEFAULT NULL,
  `whatsapp` mediumtext DEFAULT NULL,
  `telegram` mediumtext DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of rede_social
-- ----------------------------

-- ----------------------------
-- Table structure for `registro_acesso`
-- ----------------------------
DROP TABLE IF EXISTS `registro_acesso`;
CREATE TABLE `registro_acesso` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `status` int(11) NOT NULL DEFAULT 1,
  `ip` varchar(250) DEFAULT NULL,
  `navegador` varchar(250) DEFAULT NULL,
  `versao` varchar(250) DEFAULT NULL,
  `plataforma` varchar(250) DEFAULT NULL,
  `data` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of registro_acesso
-- ----------------------------

-- ----------------------------
-- Table structure for `server`
-- ----------------------------
DROP TABLE IF EXISTS `server`;
CREATE TABLE `server` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nome` varchar(250) DEFAULT NULL,
  `ip` mediumtext DEFAULT NULL,
  `porta` mediumtext NOT NULL,
  `user` mediumtext NOT NULL,
  `senha` mediumtext NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of server
-- ----------------------------
INSERT INTO `server` VALUES ('1', 'BACKUPCS', 'KzNScnJlK2FGQ3g0K3d3V2w4bWNzZz09OjpO0fWBuTNmPrwas9xUDM+x', 'bnpndGI3bHdtL0dWMTdVc21kMndldz09Ojr16JT6vVsbpJbHyAG1T16p', 'elpxelozcittaG5tZFB2TFM5QTVEdz09Ojrdkop999UE2xtJHvfQT5p+', 'bmVBd3lQSjNTZFFYcUpiSkUvTHRjZz09OjrK+pUPylfRQp7xY4J9BU7K');

-- ----------------------------
-- Table structure for `site_config`
-- ----------------------------
DROP TABLE IF EXISTS `site_config`;
CREATE TABLE `site_config` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `NomePainel` varchar(250) DEFAULT 'CSPainel',
  `LegendaPainel` varchar(250) DEFAULT 'Gerenciador de Painel',
  `TemaPainel` varchar(250) NOT NULL DEFAULT 'theme-default',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of site_config
-- ----------------------------
INSERT INTO `site_config` VALUES ('1', 'Counter-Strike', 'Gerenciamento de servidor', 'theme-dark');

-- ----------------------------
-- Table structure for `sms`
-- ----------------------------
DROP TABLE IF EXISTS `sms`;
CREATE TABLE `sms` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `user` varchar(250) DEFAULT NULL,
  `senha` varchar(250) DEFAULT NULL,
  `bloqueado` varchar(11) NOT NULL DEFAULT 'N',
  `creditos` varchar(250) DEFAULT '0',
  `valor` varchar(250) DEFAULT '0.05',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of sms
-- ----------------------------

-- ----------------------------
-- Table structure for `sms_modelo`
-- ----------------------------
DROP TABLE IF EXISTS `sms_modelo`;
CREATE TABLE `sms_modelo` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `tipo` varchar(250) DEFAULT 'Painel',
  `assunto` varchar(250) DEFAULT NULL,
  `mensagem` longtext DEFAULT NULL,
  `bloqueado` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of sms_modelo
-- ----------------------------
INSERT INTO `sms_modelo` VALUES ('1', 'admin', 'Painel', 'Dados', 'Olá senhor(a), [NMCLIENTE]. segue a baixo os dados de seu login: Login do Cliente: [LGCLIENTE] Senha do Cliente: [SNCLIENTE] Data de Vencimento: [VCCLIENTE]', 'N');

-- ----------------------------
-- Table structure for `sms_preferencias`
-- ----------------------------
DROP TABLE IF EXISTS `sms_preferencias`;
CREATE TABLE `sms_preferencias` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `DadosDeAcesso` int(11) DEFAULT NULL,
  `DadosDeAcessoTeste` int(11) DEFAULT NULL,
  `Vencimento` int(11) DEFAULT NULL,
  `Renovacao` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of sms_preferencias
-- ----------------------------

-- ----------------------------
-- Table structure for `status_servidor`
-- ----------------------------
DROP TABLE IF EXISTS `status_servidor`;
CREATE TABLE `status_servidor` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `status` varchar(11) NOT NULL DEFAULT 'N',
  `celular` varchar(250) DEFAULT NULL,
  `email` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of status_servidor
-- ----------------------------

-- ----------------------------
-- Table structure for `suporte`
-- ----------------------------
DROP TABLE IF EXISTS `suporte`;
CREATE TABLE `suporte` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `UserEmissor` varchar(250) DEFAULT NULL,
  `UserReceptor` varchar(250) DEFAULT NULL,
  `Assunto` varchar(250) DEFAULT NULL,
  `data` varchar(250) DEFAULT NULL,
  `anexo` varchar(250) DEFAULT NULL,
  `Mensagem` longtext DEFAULT NULL,
  `LidaEmissor` varchar(11) NOT NULL DEFAULT 'N',
  `LidaReceptor` varchar(11) NOT NULL DEFAULT 'N',
  `PastaEmissor` int(11) NOT NULL DEFAULT 2,
  `PastaReceptor` int(11) NOT NULL DEFAULT 1,
  `Marcacao` int(11) NOT NULL DEFAULT 5,
  `Estrela` varchar(11) NOT NULL DEFAULT 'N',
  `ExcluirEmissor` varchar(11) NOT NULL DEFAULT 'N',
  `ExcluirReceptor` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=37 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of suporte
-- ----------------------------

-- ----------------------------
-- Table structure for `suporteresp`
-- ----------------------------
DROP TABLE IF EXISTS `suporteresp`;
CREATE TABLE `suporteresp` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `id_suporte` int(11) DEFAULT NULL,
  `UserEmissor` varchar(250) DEFAULT NULL,
  `mensagem` longtext DEFAULT NULL,
  `anexo` varchar(250) DEFAULT NULL,
  `data` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=21 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of suporteresp
-- ----------------------------

-- ----------------------------
-- Table structure for `tempoteste`
-- ----------------------------
DROP TABLE IF EXISTS `tempoteste`;
CREATE TABLE `tempoteste` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tempo` int(11) NOT NULL,
  `bloqueado` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of tempoteste
-- ----------------------------
INSERT INTO `tempoteste` VALUES ('2', '1', 'N');

-- ----------------------------
-- Table structure for `tempovencimento`
-- ----------------------------
DROP TABLE IF EXISTS `tempovencimento`;
CREATE TABLE `tempovencimento` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tempo` int(11) DEFAULT NULL,
  `bloqueado` varchar(11) NOT NULL DEFAULT 'N',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of tempovencimento
-- ----------------------------
INSERT INTO `tempovencimento` VALUES ('1', '30', 'N');

-- ----------------------------
-- Table structure for `urlteste`
-- ----------------------------
DROP TABLE IF EXISTS `urlteste`;
CREATE TABLE `urlteste` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(2500) DEFAULT NULL,
  `status` varchar(11) NOT NULL DEFAULT 'N',
  `tempo` int(11) DEFAULT NULL,
  `cemail` varchar(11) NOT NULL DEFAULT 'N',
  `email` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=130 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of urlteste
-- ----------------------------

-- ----------------------------
-- Table structure for `versao`
-- ----------------------------
DROP TABLE IF EXISTS `versao`;
CREATE TABLE `versao` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `versao` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of versao
-- ----------------------------
INSERT INTO `versao` VALUES ('1', '2.6');

-- ----------------------------
-- Table structure for `whatsapp`
-- ----------------------------
DROP TABLE IF EXISTS `whatsapp`;
CREATE TABLE `whatsapp` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `user` varchar(250) DEFAULT NULL,
  `senha` varchar(250) DEFAULT NULL,
  `bloqueado` varchar(250) NOT NULL DEFAULT 'N',
  `creditos` varchar(250) DEFAULT '0',
  `valor` varchar(250) NOT NULL DEFAULT '0.06',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of whatsapp
-- ----------------------------

-- ----------------------------
-- Table structure for `whatsapp_log`
-- ----------------------------
DROP TABLE IF EXISTS `whatsapp_log`;
CREATE TABLE `whatsapp_log` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `CadUser` varchar(250) DEFAULT NULL,
  `msg` varchar(250) DEFAULT '',
  `whatsapp` varchar(250) DEFAULT '',
  `date` varchar(250) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=158 DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- ----------------------------
-- Records of whatsapp_log
-- ----------------------------
